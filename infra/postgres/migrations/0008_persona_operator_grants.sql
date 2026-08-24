CREATE TYPE kovcheg.operator_grant_status AS ENUM ('active', 'revoked');

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM kovcheg.account_auth_profiles AS profile
    JOIN kovcheg.accounts AS account ON account.id = profile.account_id
    WHERE account.kind <> 'person'
  ) THEN
    RAISE EXCEPTION 'auth state is attached to a non-person account'
      USING ERRCODE = '23514';
  END IF;
END;
$$;

CREATE FUNCTION kovcheg.enforce_person_auth_state()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  PERFORM 1
  FROM kovcheg.accounts AS account
  WHERE account.id = NEW.account_id
    AND account.kind = 'person';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'auth state requires a person account'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.enforce_person_auth_state() FROM PUBLIC;

CREATE TRIGGER account_auth_profiles_require_person
BEFORE INSERT OR UPDATE ON kovcheg.account_auth_profiles
FOR EACH ROW EXECUTE FUNCTION kovcheg.enforce_person_auth_state();

CREATE TRIGGER auth_email_challenges_require_person
BEFORE INSERT OR UPDATE ON kovcheg.auth_email_challenges
FOR EACH ROW EXECUTE FUNCTION kovcheg.enforce_person_auth_state();

CREATE TRIGGER auth_sessions_require_person
BEFORE INSERT OR UPDATE ON kovcheg.auth_sessions
FOR EACH ROW EXECUTE FUNCTION kovcheg.enforce_person_auth_state();

CREATE TABLE kovcheg.system_persona_operator_grants (
  operator_account_id uuid NOT NULL
    REFERENCES kovcheg.accounts (id) ON DELETE RESTRICT,
  persona_account_id uuid NOT NULL
    REFERENCES kovcheg.accounts (id) ON DELETE RESTRICT,
  status kovcheg.operator_grant_status NOT NULL,
  granted_at timestamptz NOT NULL,
  granted_by_account_id uuid NOT NULL
    REFERENCES kovcheg.accounts (id) ON DELETE RESTRICT,
  revoked_at timestamptz,
  revoked_by_account_id uuid
    REFERENCES kovcheg.accounts (id) ON DELETE RESTRICT,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (operator_account_id, persona_account_id),
  CONSTRAINT system_persona_operator_grants_distinct_accounts_check CHECK (
    operator_account_id <> persona_account_id
  ),
  CONSTRAINT system_persona_operator_grants_time_order_check CHECK (
    updated_at >= granted_at
  ),
  CONSTRAINT system_persona_operator_grants_state_check CHECK (
    (
      status = 'active'
      AND revoked_at IS NULL
      AND revoked_by_account_id IS NULL
    )
    OR (
      status = 'revoked'
      AND revoked_at IS NOT NULL
      AND revoked_by_account_id IS NOT NULL
      AND revoked_at >= granted_at
      AND updated_at >= revoked_at
    )
  )
);

CREATE INDEX system_persona_operator_grants_active_persona_idx
  ON kovcheg.system_persona_operator_grants (persona_account_id, operator_account_id)
  WHERE status = 'active';

CREATE FUNCTION kovcheg.enforce_persona_operator_grant_shape()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  operator_kind kovcheg.account_kind;
  persona_kind kovcheg.account_kind;
  granted_by_kind kovcheg.account_kind;
  revoked_by_kind kovcheg.account_kind;
BEGIN
  SELECT account.kind
  INTO operator_kind
  FROM kovcheg.accounts AS account
  WHERE account.id = NEW.operator_account_id;

  SELECT account.kind
  INTO persona_kind
  FROM kovcheg.accounts AS account
  WHERE account.id = NEW.persona_account_id;

  SELECT account.kind
  INTO granted_by_kind
  FROM kovcheg.accounts AS account
  WHERE account.id = NEW.granted_by_account_id;

  IF NEW.revoked_by_account_id IS NOT NULL THEN
    SELECT account.kind
    INTO revoked_by_kind
    FROM kovcheg.accounts AS account
    WHERE account.id = NEW.revoked_by_account_id;
  END IF;

  IF operator_kind IS DISTINCT FROM 'person'
    OR persona_kind IS DISTINCT FROM 'synthetic_system'
    OR granted_by_kind IS DISTINCT FROM 'person'
    OR (
      NEW.revoked_by_account_id IS NOT NULL
      AND revoked_by_kind IS DISTINCT FROM 'person'
    )
  THEN
    RAISE EXCEPTION 'operator grants require person actors and a system persona'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.enforce_persona_operator_grant_shape() FROM PUBLIC;

CREATE TRIGGER system_persona_operator_grants_enforce_shape
BEFORE INSERT OR UPDATE ON kovcheg.system_persona_operator_grants
FOR EACH ROW EXECUTE FUNCTION kovcheg.enforce_persona_operator_grant_shape();

CREATE FUNCTION kovcheg.enforce_account_kind_dependencies()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  IF NEW.kind = OLD.kind THEN
    RETURN NEW;
  END IF;

  IF NEW.kind <> 'person'
    AND (
      EXISTS (
        SELECT 1
        FROM kovcheg.account_auth_profiles AS profile
        WHERE profile.account_id = NEW.id
      )
      OR EXISTS (
        SELECT 1
        FROM kovcheg.system_persona_operator_grants AS operator_grant
        WHERE operator_grant.operator_account_id = NEW.id
          OR operator_grant.granted_by_account_id = NEW.id
          OR operator_grant.revoked_by_account_id = NEW.id
      )
    )
  THEN
    RAISE EXCEPTION 'person account dependencies prevent changing account kind'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.kind <> 'synthetic_system'
    AND EXISTS (
      SELECT 1
      FROM kovcheg.system_persona_operator_grants AS operator_grant
      WHERE operator_grant.persona_account_id = NEW.id
    )
  THEN
    RAISE EXCEPTION 'system persona dependencies prevent changing account kind'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.enforce_account_kind_dependencies() FROM PUBLIC;

CREATE TRIGGER accounts_enforce_identity_kind_dependencies
BEFORE UPDATE OF kind ON kovcheg.accounts
FOR EACH ROW EXECUTE FUNCTION kovcheg.enforce_account_kind_dependencies();

CREATE FUNCTION kovcheg.admin_grant_system_persona_operator(
  p_actor_session_verifier text,
  p_operator_account_id uuid,
  p_persona_account_id uuid,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  operator_account_id uuid,
  persona_account_id uuid,
  grant_status kovcheg.operator_grant_status,
  granted_at timestamptz,
  revoked_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  current_grant kovcheg.system_persona_operator_grants%ROWTYPE;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  PERFORM 1
  FROM kovcheg.accounts AS account
  WHERE account.id = p_operator_account_id
    AND account.kind = 'person'
    AND account.status = 'active'
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'operator grant requires an active person account'
      USING ERRCODE = '23514';
  END IF;

  PERFORM 1
  FROM kovcheg.accounts AS account
  WHERE account.id = p_persona_account_id
    AND account.kind = 'synthetic_system'
    AND account.status = 'active'
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'operator grant requires an active system persona'
      USING ERRCODE = '23514';
  END IF;

  SELECT operator_grant.*
  INTO current_grant
  FROM kovcheg.system_persona_operator_grants AS operator_grant
  WHERE operator_grant.operator_account_id = p_operator_account_id
    AND operator_grant.persona_account_id = p_persona_account_id
  FOR UPDATE;

  IF FOUND AND current_grant.status = 'active' THEN
    RAISE EXCEPTION 'operator grant is already active'
      USING ERRCODE = '23505';
  END IF;

  IF FOUND THEN
    IF p_now < current_grant.revoked_at THEN
      RAISE EXCEPTION 'operator regrant time precedes revocation'
        USING ERRCODE = '23514';
    END IF;

    UPDATE kovcheg.system_persona_operator_grants AS operator_grant
    SET status = 'active',
        granted_at = p_now,
        granted_by_account_id = actor_account_id,
        revoked_at = NULL,
        revoked_by_account_id = NULL,
        updated_at = p_now
    WHERE operator_grant.operator_account_id = p_operator_account_id
      AND operator_grant.persona_account_id = p_persona_account_id;
  ELSE
    INSERT INTO kovcheg.system_persona_operator_grants (
      operator_account_id,
      persona_account_id,
      status,
      granted_at,
      granted_by_account_id,
      updated_at
    ) VALUES (
      p_operator_account_id,
      p_persona_account_id,
      'active',
      p_now,
      actor_account_id,
      p_now
    );
  END IF;

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    'identity.persona-operator.granted',
    'system_persona',
    p_persona_account_id,
    'success',
    pg_catalog.jsonb_build_object('operatorAccountId', p_operator_account_id)
  );

  RETURN QUERY
  SELECT
    operator_grant.operator_account_id,
    operator_grant.persona_account_id,
    operator_grant.status,
    operator_grant.granted_at,
    operator_grant.revoked_at
  FROM kovcheg.system_persona_operator_grants AS operator_grant
  WHERE operator_grant.operator_account_id = p_operator_account_id
    AND operator_grant.persona_account_id = p_persona_account_id;
END;
$$;

CREATE FUNCTION kovcheg.admin_revoke_system_persona_operator(
  p_actor_session_verifier text,
  p_operator_account_id uuid,
  p_persona_account_id uuid,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  affected_grants integer;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  UPDATE kovcheg.system_persona_operator_grants AS operator_grant
  SET status = 'revoked',
      revoked_at = p_now,
      revoked_by_account_id = actor_account_id,
      updated_at = p_now
  WHERE operator_grant.operator_account_id = p_operator_account_id
    AND operator_grant.persona_account_id = p_persona_account_id
    AND operator_grant.status = 'active';
  GET DIAGNOSTICS affected_grants = ROW_COUNT;

  IF affected_grants = 0 THEN
    RETURN false;
  END IF;

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    'identity.persona-operator.revoked',
    'system_persona',
    p_persona_account_id,
    'success',
    pg_catalog.jsonb_build_object('operatorAccountId', p_operator_account_id)
  );

  RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.admin_grant_system_persona_operator(
  text, uuid, uuid, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_revoke_system_persona_operator(
  text, uuid, uuid, timestamptz, varchar
) FROM PUBLIC;

REVOKE ALL ON TABLE kovcheg.system_persona_operator_grants FROM PUBLIC;

GRANT USAGE ON TYPE kovcheg.operator_grant_status TO kovcheg_auth_runtime;
GRANT EXECUTE ON FUNCTION
  kovcheg.admin_grant_system_persona_operator(text, uuid, uuid, timestamptz, varchar),
  kovcheg.admin_revoke_system_persona_operator(text, uuid, uuid, timestamptz, varchar)
TO kovcheg_auth_runtime;

ALTER TYPE kovcheg.platform_role ADD VALUE 'chronicler';

CREATE TYPE kovcheg.domain_status AS ENUM ('incubator_participant', 'disciple');

CREATE TABLE kovcheg.account_domain_statuses (
  account_id uuid PRIMARY KEY REFERENCES kovcheg.accounts (id) ON DELETE CASCADE,
  domain_status kovcheg.domain_status NOT NULL,
  authorization_version bigint NOT NULL DEFAULT 1 CHECK (authorization_version > 0),
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO kovcheg.account_domain_statuses (account_id, domain_status)
SELECT profile.account_id, 'incubator_participant'
FROM kovcheg.account_auth_profiles AS profile
JOIN kovcheg.accounts AS account ON account.id = profile.account_id
WHERE account.kind = 'person';

INSERT INTO kovcheg.account_platform_roles (account_id, role)
SELECT profile.account_id, 'platform_administrator'
FROM kovcheg.account_auth_profiles AS profile
WHERE profile.auth_role = 'administrator'
ON CONFLICT DO NOTHING;

CREATE UNIQUE INDEX account_platform_roles_single_master_unique
  ON kovcheg.account_platform_roles (role)
  WHERE role = 'master';

CREATE FUNCTION kovcheg.enforce_master_system_persona()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  IF NEW.role = 'master' AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.accounts AS account
    WHERE account.id = NEW.account_id
      AND account.kind = 'synthetic_system'
  ) THEN
    RAISE EXCEPTION 'master role requires the system persona' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.enforce_master_system_persona() FROM PUBLIC;

CREATE TRIGGER account_platform_roles_enforce_master
BEFORE INSERT OR UPDATE ON kovcheg.account_platform_roles
FOR EACH ROW EXECUTE FUNCTION kovcheg.enforce_master_system_persona();

CREATE TABLE kovcheg.chat_domain_capability_rules (
  chat_id uuid NOT NULL REFERENCES kovcheg.chats (id) ON DELETE CASCADE,
  domain_status kovcheg.domain_status NOT NULL,
  can_read boolean NOT NULL,
  can_write boolean NOT NULL,
  PRIMARY KEY (chat_id, domain_status),
  CONSTRAINT chat_domain_capability_write_requires_read CHECK (NOT can_write OR can_read)
);

CREATE FUNCTION kovcheg.enforce_group_domain_capability_rule()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM kovcheg.chats AS chat
    WHERE chat.id = NEW.chat_id AND chat.kind = 'group'
  ) THEN
    RAISE EXCEPTION 'domain capability rules require a group chat'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.enforce_group_domain_capability_rule() FROM PUBLIC;

CREATE TRIGGER chat_domain_capability_rules_require_group
BEFORE INSERT OR UPDATE ON kovcheg.chat_domain_capability_rules
FOR EACH ROW EXECUTE FUNCTION kovcheg.enforce_group_domain_capability_rule();

CREATE FUNCTION kovcheg.read_role_capable_account(p_account_id uuid)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  account_access text,
  account_status kovcheg.account_status,
  domain_status kovcheg.domain_status,
  functional_grants text[]
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT
    account.id,
    profile.email,
    profile.display_name,
    'member'::text,
    account.status,
    domain.domain_status,
    COALESCE(
      pg_catalog.array_agg(role.role::text ORDER BY role.role::text)
        FILTER (WHERE role.role IS NOT NULL AND role.role <> 'master'),
      ARRAY[]::text[]
    )
  FROM kovcheg.accounts AS account
  JOIN kovcheg.account_auth_profiles AS profile ON profile.account_id = account.id
  JOIN kovcheg.account_domain_statuses AS domain ON domain.account_id = account.id
  LEFT JOIN kovcheg.account_platform_roles AS role ON role.account_id = account.id
  WHERE account.id = p_account_id
    AND account.kind = 'person'
  GROUP BY account.id, profile.email, profile.display_name, domain.domain_status;
$$;

REVOKE ALL ON FUNCTION kovcheg.read_role_capable_account(uuid) FROM PUBLIC;

CREATE FUNCTION kovcheg.read_current_principal_authorization(
  p_token_verifier text,
  p_now timestamptz,
  p_touch_session boolean
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  principal_account_id uuid;
  principal_session_id uuid;
  account_readback record;
  is_administrator boolean;
BEGIN
  IF p_touch_session THEN
    SELECT session.account_id, session.session_id
    INTO principal_account_id, principal_session_id
    FROM kovcheg.authenticate_auth_session(p_token_verifier, p_now) AS session;
  ELSE
    SELECT session.account_id, session.session_id
    INTO principal_account_id, principal_session_id
    FROM kovcheg.validate_auth_session(p_token_verifier, p_now) AS session;
  END IF;

  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  SELECT * INTO account_readback
  FROM kovcheg.read_role_capable_account(principal_account_id);
  IF NOT FOUND OR account_readback.account_status <> 'active' THEN
    RETURN NULL;
  END IF;

  is_administrator := 'platform_administrator' = ANY(account_readback.functional_grants);
  RETURN pg_catalog.jsonb_build_object(
    'contractVersion', 1,
    'accountAccess', account_readback.account_access,
    'accountStatus', account_readback.account_status,
    'sessionStatus', 'active',
    'userId', principal_account_id,
    'sessionId', principal_session_id,
    'domainStatus', account_readback.domain_status,
    'functionalGrants', pg_catalog.to_jsonb(account_readback.functional_grants),
    'administrativeCapabilities', pg_catalog.jsonb_build_object(
      'canManageAccounts', is_administrator,
      'canManageDomainStatus', is_administrator,
      'canManageFunctionalGrants', is_administrator
    )
  );
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.read_current_principal_authorization(
  text, timestamptz, boolean
) FROM PUBLIC;

CREATE OR REPLACE FUNCTION kovcheg.require_active_auth_administrator(
  p_actor_session_verifier text,
  p_now timestamptz
)
RETURNS uuid
LANGUAGE plpgsql
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
BEGIN
  IF p_actor_session_verifier IS NULL OR p_now IS NULL THEN
    RAISE EXCEPTION 'administrative authorization failed' USING ERRCODE = '42501';
  END IF;

  SELECT session.account_id
  INTO actor_account_id
  FROM kovcheg.auth_sessions AS session
  JOIN kovcheg.account_auth_profiles AS profile ON profile.account_id = session.account_id
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  JOIN kovcheg.account_platform_roles AS functional_grant
    ON functional_grant.account_id = account.id
   AND functional_grant.role = 'platform_administrator'
  WHERE session.token_verifier = p_actor_session_verifier
    AND session.revoked_at IS NULL
    AND p_now >= session.issued_at
    AND p_now < session.idle_expires_at
    AND p_now < session.absolute_expires_at
    AND account.status = 'active'
  FOR UPDATE OF session, profile, account, functional_grant;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'administrative authorization failed' USING ERRCODE = '42501';
  END IF;
  RETURN actor_account_id;
END;
$$;

CREATE FUNCTION kovcheg.bootstrap_role_capable_administrator(
  p_bootstrap_id text,
  p_account_id uuid,
  p_email text,
  p_display_name text
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  account_access text,
  account_status kovcheg.account_status,
  domain_status kovcheg.domain_status,
  functional_grants text[],
  created boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  bootstrap_result record;
BEGIN
  SELECT * INTO bootstrap_result
  FROM kovcheg.bootstrap_auth_administrator(
    p_bootstrap_id,
    p_account_id,
    p_email,
    p_display_name
  );

  INSERT INTO kovcheg.account_domain_statuses (account_id, domain_status)
  VALUES (bootstrap_result.account_id, 'incubator_participant')
  ON CONFLICT ON CONSTRAINT account_domain_statuses_pkey DO NOTHING;
  INSERT INTO kovcheg.account_platform_roles (account_id, role)
  VALUES (bootstrap_result.account_id, 'platform_administrator')
  ON CONFLICT DO NOTHING;

  RETURN QUERY
  SELECT account.*, bootstrap_result.created
  FROM kovcheg.read_role_capable_account(bootstrap_result.account_id) AS account;
END;
$$;

CREATE FUNCTION kovcheg.admin_create_role_capable_account(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_email text,
  p_display_name text,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  account_access text,
  account_status kovcheg.account_status,
  domain_status kovcheg.domain_status,
  functional_grants text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  created_account_id uuid;
  policy record;
BEGIN
  SELECT created.account_id INTO created_account_id
  FROM kovcheg.admin_create_auth_account(
    p_actor_session_verifier,
    p_account_id,
    p_email,
    p_display_name,
    p_now,
    p_correlation_id
  ) AS created;

  INSERT INTO kovcheg.account_domain_statuses (
    account_id,
    domain_status,
    authorization_version,
    changed_at
  ) VALUES (created_account_id, 'incubator_participant', 1, p_now);

  FOR policy IN
    SELECT rule.chat_id
    FROM kovcheg.chat_domain_capability_rules AS rule
    WHERE rule.domain_status = 'incubator_participant'
      AND rule.can_read
    ORDER BY rule.chat_id
  LOOP
    INSERT INTO kovcheg.chat_memberships (chat_id, account_id, joined_at)
    VALUES (policy.chat_id, created_account_id, p_now)
    ON CONFLICT ON CONSTRAINT chat_memberships_pkey DO UPDATE
    SET status = 'active',
        joined_at = CASE
          WHEN kovcheg.chat_memberships.status = 'revoked' THEN
            GREATEST(p_now, kovcheg.chat_memberships.revoked_at + interval '1 microsecond')
          ELSE kovcheg.chat_memberships.joined_at
        END,
        revoked_at = NULL;
  END LOOP;

  RETURN QUERY SELECT * FROM kovcheg.read_role_capable_account(created_account_id);
END;
$$;

CREATE FUNCTION kovcheg.admin_update_role_capable_account(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_email text,
  p_display_name text,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  account_access text,
  account_status kovcheg.account_status,
  domain_status kovcheg.domain_status,
  functional_grants text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  PERFORM updated.account_id
  FROM kovcheg.admin_update_auth_account(
    p_actor_session_verifier,
    p_account_id,
    p_email,
    p_display_name,
    p_now,
    p_correlation_id
  ) AS updated;

  RETURN QUERY SELECT * FROM kovcheg.read_role_capable_account(p_account_id);
END;
$$;

CREATE FUNCTION kovcheg.admin_set_role_capable_account_status(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_status kovcheg.account_status,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  account_access text,
  account_status kovcheg.account_status,
  domain_status kovcheg.domain_status,
  functional_grants text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  PERFORM updated.account_id
  FROM kovcheg.admin_set_auth_account_status(
    p_actor_session_verifier,
    p_account_id,
    p_status,
    p_now,
    p_correlation_id
  ) AS updated;

  RETURN QUERY SELECT * FROM kovcheg.read_role_capable_account(p_account_id);
END;
$$;

CREATE FUNCTION kovcheg.consume_challenge_and_read_principal(
  p_challenge_id uuid,
  p_candidate_code_verifier text,
  p_now timestamptz,
  p_session_id uuid,
  p_session_token_verifier text,
  p_session_issued_at timestamptz,
  p_idle_lifetime_ms bigint,
  p_absolute_expires_at timestamptz
)
RETURNS TABLE (outcome varchar, principal jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  challenge_result record;
BEGIN
  SELECT * INTO challenge_result
  FROM kovcheg.consume_auth_challenge_and_create_session(
    p_challenge_id,
    p_candidate_code_verifier,
    p_now,
    p_session_id,
    p_session_token_verifier,
    p_session_issued_at,
    p_idle_lifetime_ms,
    p_absolute_expires_at
  );
  outcome := challenge_result.outcome;
  principal := CASE
    WHEN outcome = 'authenticated' THEN
      kovcheg.read_current_principal_authorization(p_session_token_verifier, p_now, false)
    ELSE NULL
  END;
  RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION kovcheg.can_account_read_chat(p_account_id uuid, p_chat_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM kovcheg.accounts AS account
    JOIN kovcheg.chat_memberships AS membership ON membership.account_id = account.id
    WHERE account.id = p_account_id
      AND account.status = 'active'
      AND membership.chat_id = p_chat_id
      AND membership.status = 'active'
      AND (
        account.kind = 'synthetic_system'
        OR NOT EXISTS (
          SELECT 1 FROM kovcheg.chat_domain_capability_rules AS any_rule
          WHERE any_rule.chat_id = p_chat_id
        )
        OR EXISTS (
          SELECT 1
          FROM kovcheg.account_domain_statuses AS domain
          JOIN kovcheg.chat_domain_capability_rules AS matching_rule
            ON matching_rule.chat_id = p_chat_id
           AND matching_rule.domain_status = domain.domain_status
          WHERE domain.account_id = account.id
            AND matching_rule.can_read
        )
      )
  );
$$;

CREATE OR REPLACE FUNCTION kovcheg.can_account_post_to_chat(
  p_account_id uuid,
  p_chat_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  account_kind kovcheg.account_kind;
  chat_kind kovcheg.chat_kind;
  posting_policy kovcheg.chat_posting_policy;
  membership_is_administrator boolean;
BEGIN
  SELECT account.kind, chat.kind, chat.posting_policy, membership.is_administrator
  INTO account_kind, chat_kind, posting_policy, membership_is_administrator
  FROM kovcheg.accounts AS account
  JOIN kovcheg.chat_memberships AS membership ON membership.account_id = account.id
  JOIN kovcheg.chats AS chat ON chat.id = membership.chat_id
  WHERE account.id = p_account_id
    AND account.status = 'active'
    AND membership.chat_id = p_chat_id
    AND membership.status = 'active';

  IF NOT FOUND THEN RETURN false; END IF;

  IF account_kind = 'person'
    AND EXISTS (
      SELECT 1 FROM kovcheg.chat_domain_capability_rules AS any_rule
      WHERE any_rule.chat_id = p_chat_id
    )
    AND NOT EXISTS (
      SELECT 1
      FROM kovcheg.account_domain_statuses AS domain
      JOIN kovcheg.chat_domain_capability_rules AS matching_rule
        ON matching_rule.chat_id = p_chat_id
       AND matching_rule.domain_status = domain.domain_status
      WHERE domain.account_id = p_account_id
        AND matching_rule.can_write
    )
  THEN
    RETURN false;
  END IF;

  IF posting_policy = 'all_active_members' OR membership_is_administrator THEN RETURN true; END IF;
  IF posting_policy = 'chat_administrators' THEN RETURN false; END IF;

  RETURN EXISTS (
    SELECT 1
    FROM kovcheg.account_platform_roles AS account_role
    JOIN kovcheg.chat_allowed_posting_roles AS allowed_role
      ON allowed_role.chat_id = p_chat_id
     AND (
       allowed_role.role = account_role.role
       OR (
         chat_kind = 'group'
         AND account_role.role = 'master'
         AND allowed_role.role = 'warrior'
       )
     )
    WHERE account_role.account_id = p_account_id
  );
END;
$$;

CREATE FUNCTION kovcheg.list_account_chat_capabilities(p_account_id uuid)
RETURNS TABLE (
  id uuid,
  kind kovcheg.chat_kind,
  can_read boolean,
  can_write boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT
    chat.id,
    chat.kind,
    true,
    kovcheg.can_account_post_to_chat(p_account_id, chat.id)
  FROM kovcheg.chats AS chat
  WHERE kovcheg.can_account_read_chat(p_account_id, chat.id)
  ORDER BY chat.created_at, chat.id;
$$;

REVOKE ALL ON FUNCTION kovcheg.list_account_chat_capabilities(uuid) FROM PUBLIC;

CREATE FUNCTION kovcheg.admin_set_domain_status(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_domain_status kovcheg.domain_status,
  p_reason varchar,
  p_authorization_version bigint,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  account_access text,
  account_status kovcheg.account_status,
  domain_status kovcheg.domain_status,
  functional_grants text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  previous_status kovcheg.domain_status;
  previous_version bigint;
  chat_policy record;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );
  IF p_reason !~ '^[a-z][a-z0-9.-]{2,63}$' THEN
    RAISE EXCEPTION 'invalid authorization reason' USING ERRCODE = '23514';
  END IF;

  SELECT domain.domain_status, domain.authorization_version
  INTO previous_status, previous_version
  FROM kovcheg.account_domain_statuses AS domain
  WHERE domain.account_id = p_account_id
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'account target not found' USING ERRCODE = 'P0002'; END IF;
  IF p_authorization_version <> previous_version + 1 THEN
    RAISE EXCEPTION 'authorization version conflict' USING ERRCODE = '23505';
  END IF;

  UPDATE kovcheg.account_domain_statuses AS domain
  SET domain_status = p_domain_status,
      authorization_version = p_authorization_version,
      changed_at = p_now
  WHERE domain.account_id = p_account_id;

  FOR chat_policy IN
    SELECT
      chat.id AS chat_id,
      COALESCE(rule.can_read, false) AS can_read
    FROM kovcheg.chats AS chat
    LEFT JOIN kovcheg.chat_domain_capability_rules AS rule
      ON rule.chat_id = chat.id AND rule.domain_status = p_domain_status
    WHERE EXISTS (
      SELECT 1 FROM kovcheg.chat_domain_capability_rules AS any_rule
      WHERE any_rule.chat_id = chat.id
    )
    ORDER BY chat.id
  LOOP
    IF chat_policy.can_read THEN
      INSERT INTO kovcheg.chat_memberships (chat_id, account_id, joined_at)
      VALUES (chat_policy.chat_id, p_account_id, p_now)
      ON CONFLICT ON CONSTRAINT chat_memberships_pkey DO UPDATE
      SET status = 'active',
          joined_at = CASE
            WHEN kovcheg.chat_memberships.status = 'revoked' THEN
              GREATEST(p_now, kovcheg.chat_memberships.revoked_at + interval '1 microsecond')
            ELSE kovcheg.chat_memberships.joined_at
          END,
          revoked_at = NULL;
    ELSE
      UPDATE kovcheg.chat_memberships
      SET status = 'revoked', revoked_at = p_now
      WHERE chat_id = chat_policy.chat_id
        AND account_id = p_account_id
        AND status = 'active';
    END IF;
  END LOOP;

  migration_version := kovcheg.current_migration_version();
  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    'authorization.domain-status-set',
    'auth_account',
    p_account_id,
    'success',
    pg_catalog.jsonb_build_object(
      'previousDomainStatus', previous_status,
      'newDomainStatus', p_domain_status,
      'reasonCode', p_reason,
      'authorizationVersion', p_authorization_version
    )
  );
  RETURN QUERY SELECT * FROM kovcheg.read_role_capable_account(p_account_id);
END;
$$;

CREATE FUNCTION kovcheg.mutate_functional_grant(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_grant kovcheg.platform_role,
  p_granted boolean,
  p_reason varchar,
  p_authorization_version bigint,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  account_access text,
  account_status kovcheg.account_status,
  domain_status kovcheg.domain_status,
  functional_grants text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  previous_version bigint;
  previous_granted boolean;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );
  IF p_grant = 'master' OR p_reason !~ '^[a-z][a-z0-9.-]{2,63}$' THEN
    RAISE EXCEPTION 'invalid functional grant mutation' USING ERRCODE = '23514';
  END IF;

  SELECT authorization_version INTO previous_version
  FROM kovcheg.account_domain_statuses AS domain
  WHERE domain.account_id = p_account_id
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'account target not found' USING ERRCODE = 'P0002'; END IF;
  IF p_authorization_version <> previous_version + 1 THEN
    RAISE EXCEPTION 'authorization version conflict' USING ERRCODE = '23505';
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM kovcheg.account_platform_roles AS account_role
    WHERE account_role.account_id = p_account_id AND account_role.role = p_grant
  ) INTO previous_granted;
  IF p_granted AND previous_granted THEN
    RAISE EXCEPTION 'functional grant already exists' USING ERRCODE = '23505';
  ELSIF NOT p_granted AND NOT previous_granted THEN
    RAISE EXCEPTION 'functional grant not found' USING ERRCODE = 'P0002';
  END IF;

  IF p_granted THEN
    INSERT INTO kovcheg.account_platform_roles (account_id, role, granted_at)
    VALUES (p_account_id, p_grant, p_now);
  ELSE
    DELETE FROM kovcheg.account_platform_roles AS account_role
    WHERE account_role.account_id = p_account_id AND account_role.role = p_grant;
  END IF;

  UPDATE kovcheg.account_domain_statuses AS domain
  SET authorization_version = p_authorization_version, changed_at = p_now
  WHERE domain.account_id = p_account_id;

  migration_version := kovcheg.current_migration_version();
  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    CASE WHEN p_granted THEN 'authorization.functional-grant.granted'
         ELSE 'authorization.functional-grant.revoked' END,
    'auth_account',
    p_account_id,
    'success',
    pg_catalog.jsonb_build_object(
      'functionalGrant', p_grant,
      'previousGranted', previous_granted,
      'newGranted', p_granted,
      'reasonCode', p_reason,
      'authorizationVersion', p_authorization_version
    )
  );
  RETURN QUERY SELECT * FROM kovcheg.read_role_capable_account(p_account_id);
END;
$$;

CREATE FUNCTION kovcheg.admin_grant_functional_grant(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_grant kovcheg.platform_role,
  p_reason varchar,
  p_authorization_version bigint,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  account_access text,
  account_status kovcheg.account_status,
  domain_status kovcheg.domain_status,
  functional_grants text[]
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT * FROM kovcheg.mutate_functional_grant(
    p_actor_session_verifier, p_account_id, p_grant, true, p_reason,
    p_authorization_version, p_now, p_correlation_id
  );
$$;

CREATE FUNCTION kovcheg.admin_revoke_functional_grant(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_grant kovcheg.platform_role,
  p_reason varchar,
  p_authorization_version bigint,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  account_access text,
  account_status kovcheg.account_status,
  domain_status kovcheg.domain_status,
  functional_grants text[]
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT * FROM kovcheg.mutate_functional_grant(
    p_actor_session_verifier, p_account_id, p_grant, false, p_reason,
    p_authorization_version, p_now, p_correlation_id
  );
$$;

REVOKE ALL ON FUNCTION kovcheg.bootstrap_role_capable_administrator(
  text, uuid, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_create_role_capable_account(
  text, uuid, text, text, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_update_role_capable_account(
  text, uuid, text, text, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_set_role_capable_account_status(
  text, uuid, kovcheg.account_status, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.consume_challenge_and_read_principal(
  uuid, text, timestamptz, uuid, text, timestamptz, bigint, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_set_domain_status(
  text, uuid, kovcheg.domain_status, varchar, bigint, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.mutate_functional_grant(
  text, uuid, kovcheg.platform_role, boolean, varchar, bigint, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_grant_functional_grant(
  text, uuid, kovcheg.platform_role, varchar, bigint, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_revoke_functional_grant(
  text, uuid, kovcheg.platform_role, varchar, bigint, timestamptz, varchar
) FROM PUBLIC;

REVOKE EXECUTE ON FUNCTION kovcheg.bootstrap_auth_administrator(text, uuid, text, text)
FROM kovcheg_auth_runtime;
REVOKE EXECUTE ON FUNCTION kovcheg.admin_create_auth_account(
  text, uuid, text, text, timestamptz, varchar
) FROM kovcheg_auth_runtime;

GRANT USAGE ON TYPE kovcheg.domain_status, kovcheg.platform_role
TO kovcheg_auth_runtime;
GRANT EXECUTE ON FUNCTION
  kovcheg.bootstrap_role_capable_administrator(text, uuid, text, text),
  kovcheg.admin_create_role_capable_account(text, uuid, text, text, timestamptz, varchar),
  kovcheg.admin_update_role_capable_account(text, uuid, text, text, timestamptz, varchar),
  kovcheg.admin_set_role_capable_account_status(
    text, uuid, kovcheg.account_status, timestamptz, varchar
  ),
  kovcheg.consume_challenge_and_read_principal(
    uuid, text, timestamptz, uuid, text, timestamptz, bigint, timestamptz
  ),
  kovcheg.read_current_principal_authorization(text, timestamptz, boolean),
  kovcheg.read_role_capable_account(uuid),
  kovcheg.admin_set_domain_status(
    text, uuid, kovcheg.domain_status, varchar, bigint, timestamptz, varchar
  ),
  kovcheg.admin_grant_functional_grant(
    text, uuid, kovcheg.platform_role, varchar, bigint, timestamptz, varchar
  ),
  kovcheg.admin_revoke_functional_grant(
    text, uuid, kovcheg.platform_role, varchar, bigint, timestamptz, varchar
  )
TO kovcheg_auth_runtime;

GRANT EXECUTE ON FUNCTION kovcheg.list_account_chat_capabilities(uuid)
TO kovcheg_runtime;

COMMENT ON TABLE kovcheg.chat_domain_capability_rules IS
  'Server-configured current read and write policy by domain status; no chat name is hard-coded.';
COMMENT ON FUNCTION kovcheg.read_current_principal_authorization(text, timestamptz, boolean) IS
  'Versioned server-authoritative account, session, domain-status, functional-grant, and administrative-capability readback.';

CREATE TYPE kovcheg.auth_passkey_transport AS ENUM (
  'ble',
  'hybrid',
  'internal',
  'nfc',
  'smart-card',
  'usb'
);

CREATE TYPE kovcheg.auth_passkey_sign_count_status AS ENUM (
  'not_supported',
  'advanced',
  'not_advanced',
  'regressed'
);

CREATE TABLE kovcheg.auth_passkey_credentials (
  id uuid PRIMARY KEY,
  account_id uuid NOT NULL
    REFERENCES kovcheg.account_auth_profiles (account_id) ON DELETE CASCADE,
  credential_id bytea NOT NULL UNIQUE,
  public_key bytea NOT NULL,
  sign_count bigint NOT NULL,
  transports kovcheg.auth_passkey_transport[] NOT NULL DEFAULT '{}',
  aaguid uuid NOT NULL,
  attestation_format varchar(32) NOT NULL,
  registered_backup_eligible boolean NOT NULL,
  registered_backup_state boolean NOT NULL,
  last_backup_eligible boolean NOT NULL,
  last_backup_state boolean NOT NULL,
  created_by_session_id uuid
    REFERENCES kovcheg.auth_sessions (id) ON DELETE SET NULL,
  registration_correlation_id varchar(128) NOT NULL,
  created_at timestamptz NOT NULL,
  last_used_at timestamptz,
  revoked_at timestamptz,
  CONSTRAINT auth_passkey_credentials_id_account_unique UNIQUE (id, account_id),
  CONSTRAINT auth_passkey_credentials_credential_id_check CHECK (
    octet_length(credential_id) BETWEEN 1 AND 1024
  ),
  CONSTRAINT auth_passkey_credentials_public_key_check CHECK (
    octet_length(public_key) BETWEEN 1 AND 8192
  ),
  CONSTRAINT auth_passkey_credentials_sign_count_check CHECK (
    sign_count BETWEEN 0 AND 4294967295
  ),
  CONSTRAINT auth_passkey_credentials_transports_check CHECK (
    cardinality(transports) BETWEEN 0 AND 6
  ),
  CONSTRAINT auth_passkey_credentials_attestation_format_check CHECK (
    attestation_format = pg_catalog.lower(pg_catalog.btrim(attestation_format))
    AND attestation_format ~ '^[a-z0-9][a-z0-9._-]{0,31}$'
  ),
  CONSTRAINT auth_passkey_credentials_registered_backup_check CHECK (
    NOT registered_backup_state OR registered_backup_eligible
  ),
  CONSTRAINT auth_passkey_credentials_last_backup_check CHECK (
    NOT last_backup_state OR last_backup_eligible
  ),
  CONSTRAINT auth_passkey_credentials_registration_correlation_check CHECK (
    registration_correlation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  ),
  CONSTRAINT auth_passkey_credentials_lifecycle_check CHECK (
    (last_used_at IS NULL OR last_used_at >= created_at)
    AND (revoked_at IS NULL OR revoked_at >= created_at)
  )
);

CREATE INDEX auth_passkey_credentials_account_live_idx
  ON kovcheg.auth_passkey_credentials (account_id, created_at, id)
  WHERE revoked_at IS NULL;

COMMENT ON COLUMN kovcheg.auth_passkey_credentials.credential_id IS
  'Opaque WebAuthn credential identifier required for lookup; never include it in audit details or logs.';
COMMENT ON COLUMN kovcheg.auth_passkey_credentials.public_key IS
  'WebAuthn credential public key only. Private key material never reaches PostgreSQL.';
COMMENT ON COLUMN kovcheg.auth_passkey_credentials.transports IS
  'Authenticator transport hints only; user-assigned device names and contact data are not stored.';

CREATE TABLE kovcheg.auth_passkey_assertion_evidence (
  id uuid PRIMARY KEY,
  passkey_id uuid NOT NULL,
  account_id uuid NOT NULL,
  application_session_id uuid NOT NULL UNIQUE
    REFERENCES kovcheg.auth_sessions (id) ON DELETE RESTRICT,
  previous_sign_count bigint NOT NULL,
  observed_sign_count bigint NOT NULL,
  resulting_sign_count bigint NOT NULL,
  sign_count_status kovcheg.auth_passkey_sign_count_status NOT NULL,
  previous_backup_eligible boolean NOT NULL,
  previous_backup_state boolean NOT NULL,
  observed_backup_eligible boolean NOT NULL,
  observed_backup_state boolean NOT NULL,
  backup_eligibility_changed boolean NOT NULL,
  backup_state_changed boolean NOT NULL,
  user_verified boolean NOT NULL,
  correlation_id varchar(128) NOT NULL,
  occurred_at timestamptz NOT NULL,
  CONSTRAINT auth_passkey_assertion_evidence_passkey_account_fk
    FOREIGN KEY (passkey_id, account_id)
    REFERENCES kovcheg.auth_passkey_credentials (id, account_id)
    ON DELETE RESTRICT,
  CONSTRAINT auth_passkey_assertion_evidence_sign_count_check CHECK (
    previous_sign_count BETWEEN 0 AND 4294967295
    AND observed_sign_count BETWEEN 0 AND 4294967295
    AND resulting_sign_count BETWEEN 0 AND 4294967295
    AND resulting_sign_count = GREATEST(previous_sign_count, observed_sign_count)
  ),
  CONSTRAINT auth_passkey_assertion_evidence_backup_check CHECK (
    (NOT previous_backup_state OR previous_backup_eligible)
    AND (NOT observed_backup_state OR observed_backup_eligible)
  ),
  CONSTRAINT auth_passkey_assertion_evidence_uv_check CHECK (user_verified),
  CONSTRAINT auth_passkey_assertion_evidence_correlation_check CHECK (
    correlation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  )
);

CREATE INDEX auth_passkey_assertion_evidence_passkey_idx
  ON kovcheg.auth_passkey_assertion_evidence (passkey_id, occurred_at, id);
CREATE INDEX auth_passkey_assertion_evidence_account_idx
  ON kovcheg.auth_passkey_assertion_evidence (account_id, occurred_at, id);

CREATE TRIGGER auth_passkey_assertion_evidence_reject_mutation
BEFORE UPDATE OR DELETE ON kovcheg.auth_passkey_assertion_evidence
FOR EACH ROW EXECUTE FUNCTION kovcheg.reject_append_only_mutation();
CREATE TRIGGER auth_passkey_assertion_evidence_reject_truncate
BEFORE TRUNCATE ON kovcheg.auth_passkey_assertion_evidence
FOR EACH STATEMENT EXECUTE FUNCTION kovcheg.reject_append_only_mutation();

CREATE FUNCTION kovcheg.auth_passkey_audit(
  p_correlation_id varchar,
  p_actor_account_id uuid,
  p_action varchar,
  p_passkey_id uuid,
  p_details jsonb
)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  migration_version text;
BEGIN
  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    p_actor_account_id,
    p_action,
    'auth_passkey_credential',
    p_passkey_id,
    'success',
    p_details
  );
END;
$$;

CREATE FUNCTION kovcheg.register_auth_passkey(
  p_application_session_verifier text,
  p_passkey_id uuid,
  p_credential_id bytea,
  p_public_key bytea,
  p_sign_count bigint,
  p_transports kovcheg.auth_passkey_transport[],
  p_aaguid uuid,
  p_attestation_format text,
  p_backup_eligible boolean,
  p_backup_state boolean,
  p_user_verified boolean,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  passkey_id uuid,
  account_id uuid,
  created_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  authorized_account_id uuid;
  authorized_session_id uuid;
  normalized_transports kovcheg.auth_passkey_transport[];
  normalized_attestation_format text := pg_catalog.lower(
    pg_catalog.btrim(p_attestation_format)
  );
BEGIN
  IF p_user_verified IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'passkey user verification is required' USING ERRCODE = '42501';
  END IF;

  IF p_passkey_id IS NULL
    OR p_credential_id IS NULL
    OR octet_length(p_credential_id) NOT BETWEEN 1 AND 1024
    OR p_public_key IS NULL
    OR octet_length(p_public_key) NOT BETWEEN 1 AND 8192
    OR p_sign_count IS NULL
    OR p_sign_count NOT BETWEEN 0 AND 4294967295
    OR p_aaguid IS NULL
    OR normalized_attestation_format IS NULL
    OR normalized_attestation_format !~ '^[a-z0-9][a-z0-9._-]{0,31}$'
    OR p_backup_eligible IS NULL
    OR p_backup_state IS NULL
    OR (p_backup_state AND NOT p_backup_eligible)
    OR p_now IS NULL
    OR p_correlation_id IS NULL
    OR p_correlation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  THEN
    RAISE EXCEPTION 'invalid passkey registration input' USING ERRCODE = '23514';
  END IF;

  SELECT session.account_id, session.id
  INTO authorized_account_id, authorized_session_id
  FROM kovcheg.auth_sessions AS session
  JOIN kovcheg.account_auth_profiles AS profile
    ON profile.account_id = session.account_id
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE session.token_verifier = p_application_session_verifier
    AND session.revoked_at IS NULL
    AND p_now >= session.issued_at
    AND p_now < session.idle_expires_at
    AND p_now < session.absolute_expires_at
    AND account.kind = 'person'
    AND account.status = 'active'
  FOR UPDATE OF session, profile, account;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey registration authorization failed' USING ERRCODE = '42501';
  END IF;

  SELECT COALESCE(
    pg_catalog.array_agg(
      DISTINCT transport_value.transport
      ORDER BY transport_value.transport
    ),
    ARRAY[]::kovcheg.auth_passkey_transport[]
  )
  INTO normalized_transports
  FROM pg_catalog.unnest(
    COALESCE(p_transports, ARRAY[]::kovcheg.auth_passkey_transport[])
  ) AS transport_value(transport);

  INSERT INTO kovcheg.auth_passkey_credentials (
    id,
    account_id,
    credential_id,
    public_key,
    sign_count,
    transports,
    aaguid,
    attestation_format,
    registered_backup_eligible,
    registered_backup_state,
    last_backup_eligible,
    last_backup_state,
    created_by_session_id,
    registration_correlation_id,
    created_at
  ) VALUES (
    p_passkey_id,
    authorized_account_id,
    p_credential_id,
    p_public_key,
    p_sign_count,
    normalized_transports,
    p_aaguid,
    normalized_attestation_format,
    p_backup_eligible,
    p_backup_state,
    p_backup_eligible,
    p_backup_state,
    authorized_session_id,
    p_correlation_id,
    p_now
  );

  PERFORM kovcheg.auth_passkey_audit(
    p_correlation_id,
    authorized_account_id,
    'auth.passkey.registered',
    p_passkey_id,
    pg_catalog.jsonb_build_object(
      'transportCount', cardinality(normalized_transports),
      'backupEligible', p_backup_eligible,
      'backupState', p_backup_state
    )
  );

  passkey_id := p_passkey_id;
  account_id := authorized_account_id;
  created_at := p_now;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION kovcheg.read_auth_passkey_by_credential_id(
  p_credential_id bytea,
  p_now timestamptz
)
RETURNS TABLE (
  passkey_id uuid,
  account_id uuid,
  public_key bytea,
  sign_count bigint,
  transports kovcheg.auth_passkey_transport[],
  aaguid uuid,
  attestation_format varchar,
  registered_backup_eligible boolean,
  registered_backup_state boolean,
  last_backup_eligible boolean,
  last_backup_state boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT
    passkey.id,
    passkey.account_id,
    passkey.public_key,
    passkey.sign_count,
    passkey.transports,
    passkey.aaguid,
    passkey.attestation_format,
    passkey.registered_backup_eligible,
    passkey.registered_backup_state,
    passkey.last_backup_eligible,
    passkey.last_backup_state
  FROM kovcheg.auth_passkey_credentials AS passkey
  JOIN kovcheg.accounts AS account ON account.id = passkey.account_id
  WHERE passkey.credential_id = p_credential_id
    AND passkey.revoked_at IS NULL
    AND p_now >= passkey.created_at
    AND account.kind = 'person'
    AND account.status = 'active';
$$;

CREATE FUNCTION kovcheg.complete_auth_passkey_login(
  p_credential_id bytea,
  p_expected_sign_count bigint,
  p_observed_sign_count bigint,
  p_observed_backup_eligible boolean,
  p_observed_backup_state boolean,
  p_user_verified boolean,
  p_assertion_id uuid,
  p_session_id uuid,
  p_session_token_verifier text,
  p_idle_lifetime_ms bigint,
  p_absolute_expires_at timestamptz,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  outcome varchar,
  account_id uuid,
  session_id uuid,
  auth_roles kovcheg.auth_account_role[],
  sign_count_status kovcheg.auth_passkey_sign_count_status,
  resulting_sign_count bigint,
  reused boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  passkey_record record;
  existing_evidence record;
  initial_idle_expires_at timestamptz;
  evaluated_status kovcheg.auth_passkey_sign_count_status;
  evaluated_resulting_count bigint;
  evaluated_backup_eligibility_changed boolean;
  evaluated_backup_state_changed boolean;
BEGIN
  IF p_user_verified IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'passkey user verification is required' USING ERRCODE = '42501';
  END IF;

  IF p_credential_id IS NULL
    OR octet_length(p_credential_id) NOT BETWEEN 1 AND 1024
    OR p_expected_sign_count IS NULL
    OR p_expected_sign_count NOT BETWEEN 0 AND 4294967295
    OR p_observed_sign_count IS NULL
    OR p_observed_sign_count NOT BETWEEN 0 AND 4294967295
    OR p_observed_backup_eligible IS NULL
    OR p_observed_backup_state IS NULL
    OR (p_observed_backup_state AND NOT p_observed_backup_eligible)
    OR p_assertion_id IS NULL
    OR p_session_id IS NULL
    OR p_session_token_verifier IS NULL
    OR p_session_token_verifier !~ '^[A-Za-z0-9_-]{43}$'
    OR p_idle_lifetime_ms IS NULL
    OR p_idle_lifetime_ms <= 0
    OR p_absolute_expires_at IS NULL
    OR p_now IS NULL
    OR p_absolute_expires_at <= p_now
    OR p_correlation_id IS NULL
    OR p_correlation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  THEN
    RAISE EXCEPTION 'invalid passkey login input' USING ERRCODE = '23514';
  END IF;

  SELECT
    passkey.*,
    profile.auth_role,
    account.status AS account_status,
    account.kind AS account_kind
  INTO passkey_record
  FROM kovcheg.auth_passkey_credentials AS passkey
  JOIN kovcheg.account_auth_profiles AS profile
    ON profile.account_id = passkey.account_id
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE passkey.credential_id = p_credential_id
  FOR UPDATE OF passkey, profile, account;

  IF NOT FOUND
    OR passkey_record.revoked_at IS NOT NULL
    OR passkey_record.account_status <> 'active'
    OR passkey_record.account_kind <> 'person'
    OR p_now < passkey_record.created_at
  THEN
    RETURN;
  END IF;

  SELECT
    evidence.*,
    session.token_verifier AS recorded_session_token_verifier,
    session.account_id AS recorded_session_account_id,
    session.issued_at AS recorded_session_issued_at,
    session.idle_expires_at AS recorded_session_idle_expires_at,
    session.absolute_expires_at AS recorded_session_absolute_expires_at,
    session.revoked_at AS recorded_session_revoked_at
  INTO existing_evidence
  FROM kovcheg.auth_passkey_assertion_evidence AS evidence
  JOIN kovcheg.auth_sessions AS session
    ON session.id = evidence.application_session_id
  WHERE evidence.id = p_assertion_id;

  IF FOUND THEN
    IF existing_evidence.passkey_id <> passkey_record.id
      OR existing_evidence.previous_sign_count <> p_expected_sign_count
      OR existing_evidence.observed_sign_count <> p_observed_sign_count
      OR existing_evidence.observed_backup_eligible <> p_observed_backup_eligible
      OR existing_evidence.observed_backup_state <> p_observed_backup_state
      OR existing_evidence.application_session_id <> p_session_id
      OR existing_evidence.recorded_session_account_id <> passkey_record.account_id
      OR existing_evidence.recorded_session_token_verifier <> p_session_token_verifier
      OR existing_evidence.correlation_id <> p_correlation_id
    THEN
      RAISE EXCEPTION 'passkey assertion idempotency conflict' USING ERRCODE = '23505';
    END IF;

    IF existing_evidence.recorded_session_revoked_at IS NOT NULL
      OR p_now < existing_evidence.recorded_session_issued_at
      OR p_now >= existing_evidence.recorded_session_idle_expires_at
      OR p_now >= existing_evidence.recorded_session_absolute_expires_at
    THEN
      RETURN;
    END IF;

    outcome := 'authenticated';
    account_id := existing_evidence.account_id;
    session_id := existing_evidence.application_session_id;
    auth_roles := ARRAY[passkey_record.auth_role]::kovcheg.auth_account_role[];
    sign_count_status := existing_evidence.sign_count_status;
    resulting_sign_count := existing_evidence.resulting_sign_count;
    reused := true;
    RETURN NEXT;
    RETURN;
  END IF;

  IF passkey_record.sign_count <> p_expected_sign_count THEN
    RAISE EXCEPTION 'passkey sign count changed concurrently' USING ERRCODE = '40001';
  END IF;

  evaluated_status := CASE
    WHEN passkey_record.sign_count = 0 AND p_observed_sign_count = 0
      THEN 'not_supported'
    WHEN p_observed_sign_count > passkey_record.sign_count
      THEN 'advanced'
    WHEN p_observed_sign_count = passkey_record.sign_count
      THEN 'not_advanced'
    ELSE 'regressed'
  END;
  evaluated_resulting_count := GREATEST(
    passkey_record.sign_count,
    p_observed_sign_count
  );
  evaluated_backup_eligibility_changed :=
    passkey_record.last_backup_eligible <> p_observed_backup_eligible;
  evaluated_backup_state_changed :=
    passkey_record.last_backup_state <> p_observed_backup_state
    OR passkey_record.last_backup_eligible <> p_observed_backup_eligible;

  initial_idle_expires_at := LEAST(
    p_absolute_expires_at,
    p_now + (p_idle_lifetime_ms * interval '1 millisecond')
  );

  INSERT INTO kovcheg.auth_sessions (
    id,
    account_id,
    token_verifier,
    issued_at,
    last_seen_at,
    idle_lifetime_ms,
    idle_expires_at,
    absolute_expires_at
  ) VALUES (
    p_session_id,
    passkey_record.account_id,
    p_session_token_verifier,
    p_now,
    p_now,
    p_idle_lifetime_ms,
    initial_idle_expires_at,
    p_absolute_expires_at
  );

  UPDATE kovcheg.auth_passkey_credentials AS passkey
  SET sign_count = evaluated_resulting_count,
      last_backup_eligible = p_observed_backup_eligible,
      last_backup_state = p_observed_backup_state,
      last_used_at = p_now
  WHERE passkey.id = passkey_record.id;

  INSERT INTO kovcheg.auth_passkey_assertion_evidence (
    id,
    passkey_id,
    account_id,
    application_session_id,
    previous_sign_count,
    observed_sign_count,
    resulting_sign_count,
    sign_count_status,
    previous_backup_eligible,
    previous_backup_state,
    observed_backup_eligible,
    observed_backup_state,
    backup_eligibility_changed,
    backup_state_changed,
    user_verified,
    correlation_id,
    occurred_at
  ) VALUES (
    p_assertion_id,
    passkey_record.id,
    passkey_record.account_id,
    p_session_id,
    passkey_record.sign_count,
    p_observed_sign_count,
    evaluated_resulting_count,
    evaluated_status,
    passkey_record.last_backup_eligible,
    passkey_record.last_backup_state,
    p_observed_backup_eligible,
    p_observed_backup_state,
    evaluated_backup_eligibility_changed,
    evaluated_backup_state_changed,
    true,
    p_correlation_id,
    p_now
  );

  PERFORM kovcheg.auth_passkey_audit(
    p_correlation_id,
    passkey_record.account_id,
    'auth.passkey.authenticated',
    passkey_record.id,
    pg_catalog.jsonb_build_object(
      'signCountStatus', evaluated_status,
      'backupEligibilityChanged', evaluated_backup_eligibility_changed,
      'backupStateChanged', evaluated_backup_state_changed,
      'syncedPasskey', p_observed_backup_eligible
    )
  );

  outcome := 'authenticated';
  account_id := passkey_record.account_id;
  session_id := p_session_id;
  auth_roles := ARRAY[passkey_record.auth_role]::kovcheg.auth_account_role[];
  sign_count_status := evaluated_status;
  resulting_sign_count := evaluated_resulting_count;
  reused := false;
  RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION kovcheg.admin_security_reset_auth_access(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  revoked_family_count integer := 0;
  revoked_gate_session_count integer := 0;
  revoked_passkey_count integer := 0;
  invalidated_challenge_count integer := 0;
  revoked_application_session_count integer := 0;
  result jsonb;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  PERFORM 1
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.account_id = p_account_id
  FOR UPDATE OF profile, account;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'auth account target not found' USING ERRCODE = 'P0002';
  END IF;

  UPDATE kovcheg.auth_personal_gate_families AS family
  SET status = 'revoked',
      revoked_at = GREATEST(p_now, family.issued_at),
      paused_until = NULL
  WHERE family.account_id = p_account_id
    AND family.status IN ('active', 'suspended');
  GET DIAGNOSTICS revoked_family_count = ROW_COUNT;

  UPDATE kovcheg.auth_personal_gate_sessions AS gate_session
  SET revoked_at = GREATEST(p_now, gate_session.issued_at)
  WHERE gate_session.account_id = p_account_id
    AND gate_session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_gate_session_count = ROW_COUNT;

  UPDATE kovcheg.auth_passkey_credentials AS passkey
  SET revoked_at = GREATEST(p_now, passkey.created_at)
  WHERE passkey.account_id = p_account_id
    AND passkey.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_passkey_count = ROW_COUNT;

  UPDATE kovcheg.auth_email_challenges AS challenge
  SET invalidated_at = GREATEST(p_now, challenge.issued_at)
  WHERE challenge.account_id = p_account_id
    AND challenge.used_at IS NULL
    AND challenge.invalidated_at IS NULL;
  GET DIAGNOSTICS invalidated_challenge_count = ROW_COUNT;

  UPDATE kovcheg.auth_sessions AS session
  SET revoked_at = GREATEST(p_now, session.issued_at)
  WHERE session.account_id = p_account_id
    AND session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_application_session_count = ROW_COUNT;

  result := pg_catalog.jsonb_build_object(
    'revokedFamilyCount', revoked_family_count,
    'revokedGateSessionCount', revoked_gate_session_count,
    'revokedPasskeyCount', revoked_passkey_count,
    'invalidatedChallengeCount', invalidated_challenge_count,
    'revokedApplicationSessionCount', revoked_application_session_count
  );

  PERFORM kovcheg.auth_personal_gate_audit(
    p_correlation_id,
    actor_account_id,
    'auth.personal-gate.security-reset',
    'auth_account',
    p_account_id,
    result
  );

  RETURN result;
END;
$$;

CREATE FUNCTION kovcheg.revoke_auth_passkeys_on_account_deactivation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  effective_time timestamptz;
BEGIN
  IF NEW.status <> 'active' AND OLD.status IS DISTINCT FROM NEW.status THEN
    effective_time := COALESCE(NEW.deactivated_at, pg_catalog.clock_timestamp());

    UPDATE kovcheg.auth_passkey_credentials AS passkey
    SET revoked_at = GREATEST(effective_time, passkey.created_at)
    WHERE passkey.account_id = NEW.id
      AND passkey.revoked_at IS NULL;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER accounts_revoke_passkeys_on_deactivation
AFTER UPDATE OF status ON kovcheg.accounts
FOR EACH ROW EXECUTE FUNCTION kovcheg.revoke_auth_passkeys_on_account_deactivation();

REVOKE ALL ON ALL TABLES IN SCHEMA kovcheg FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA kovcheg FROM PUBLIC;

REVOKE ALL ON FUNCTION kovcheg.auth_passkey_audit(
  varchar, uuid, varchar, uuid, jsonb
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.register_auth_passkey(
  text, uuid, bytea, bytea, bigint, kovcheg.auth_passkey_transport[], uuid,
  text, boolean, boolean, boolean, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.read_auth_passkey_by_credential_id(
  bytea, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.complete_auth_passkey_login(
  bytea, bigint, bigint, boolean, boolean, boolean, uuid, uuid, text, bigint,
  timestamptz, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.revoke_auth_passkeys_on_account_deactivation()
FROM PUBLIC;

GRANT USAGE ON TYPE kovcheg.auth_passkey_transport,
  kovcheg.auth_passkey_sign_count_status
TO kovcheg_auth_runtime;

GRANT EXECUTE ON FUNCTION
  kovcheg.register_auth_passkey(
    text, uuid, bytea, bytea, bigint, kovcheg.auth_passkey_transport[], uuid,
    text, boolean, boolean, boolean, timestamptz, varchar
  ),
  kovcheg.read_auth_passkey_by_credential_id(bytea, timestamptz),
  kovcheg.complete_auth_passkey_login(
    bytea, bigint, bigint, boolean, boolean, boolean, uuid, uuid, text, bigint,
    timestamptz, timestamptz, varchar
  )
TO kovcheg_auth_runtime;

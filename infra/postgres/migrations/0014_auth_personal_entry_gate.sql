CREATE TYPE kovcheg.auth_personal_gate_family_status AS ENUM (
  'active',
  'suspended',
  'revoked'
);

CREATE TABLE kovcheg.auth_personal_gate_families (
  id uuid PRIMARY KEY,
  account_id uuid NOT NULL
    REFERENCES kovcheg.account_auth_profiles (account_id) ON DELETE CASCADE,
  code_verifier varchar(43) NOT NULL UNIQUE,
  status kovcheg.auth_personal_gate_family_status NOT NULL DEFAULT 'active',
  issued_at timestamptz NOT NULL,
  revoked_at timestamptz,
  suspended_at timestamptz,
  mismatch_window_started_at timestamptz,
  mismatch_count integer NOT NULL DEFAULT 0,
  pause_window_started_at timestamptz,
  pause_count integer NOT NULL DEFAULT 0,
  paused_until timestamptz,
  CONSTRAINT auth_personal_gate_families_verifier_check CHECK (
    code_verifier ~ '^[A-Za-z0-9_-]{43}$'
  ),
  CONSTRAINT auth_personal_gate_families_state_check CHECK (
    (status = 'active' AND revoked_at IS NULL AND suspended_at IS NULL)
    OR (status = 'suspended' AND revoked_at IS NULL AND suspended_at IS NOT NULL)
    OR (status = 'revoked' AND revoked_at IS NOT NULL)
  ),
  CONSTRAINT auth_personal_gate_families_state_time_check CHECK (
    (revoked_at IS NULL OR revoked_at >= issued_at)
    AND (suspended_at IS NULL OR suspended_at >= issued_at)
  ),
  CONSTRAINT auth_personal_gate_families_mismatch_check CHECK (
    mismatch_count BETWEEN 0 AND 4
    AND ((mismatch_count = 0 AND mismatch_window_started_at IS NULL)
      OR (mismatch_count > 0 AND mismatch_window_started_at IS NOT NULL))
  ),
  CONSTRAINT auth_personal_gate_families_pause_check CHECK (
    pause_count BETWEEN 0 AND 3
    AND ((pause_count = 0 AND pause_window_started_at IS NULL)
      OR (pause_count > 0 AND pause_window_started_at IS NOT NULL))
    AND (paused_until IS NULL OR paused_until > issued_at)
    AND (status = 'active' OR paused_until IS NULL)
  )
);

CREATE UNIQUE INDEX auth_personal_gate_families_one_current_per_account_unique
  ON kovcheg.auth_personal_gate_families (account_id)
  WHERE status IN ('active', 'suspended');
CREATE UNIQUE INDEX auth_personal_gate_families_id_account_unique
  ON kovcheg.auth_personal_gate_families (id, account_id);

COMMENT ON COLUMN kovcheg.auth_personal_gate_families.code_verifier IS
  'Server-computed HMAC verifier only. The raw entry code and HMAC pepper remain outside PostgreSQL.';

CREATE TABLE kovcheg.auth_personal_gate_sessions (
  id uuid PRIMARY KEY,
  family_id uuid NOT NULL,
  account_id uuid NOT NULL,
  token_verifier varchar(43) NOT NULL UNIQUE,
  client_idempotency_key varchar(128) NOT NULL,
  issued_at timestamptz NOT NULL,
  last_login_at timestamptz,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CONSTRAINT auth_personal_gate_sessions_family_account_fk
    FOREIGN KEY (family_id, account_id)
    REFERENCES kovcheg.auth_personal_gate_families (id, account_id)
    ON DELETE CASCADE,
  CONSTRAINT auth_personal_gate_sessions_verifier_check CHECK (
    token_verifier ~ '^[A-Za-z0-9_-]{43}$'
  ),
  CONSTRAINT auth_personal_gate_sessions_idempotency_check CHECK (
    client_idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
  ),
  CONSTRAINT auth_personal_gate_sessions_lifetime_check CHECK (
    expires_at > issued_at
    AND expires_at <= COALESCE(last_login_at, issued_at) + interval '7 days'
    AND (last_login_at IS NULL OR last_login_at >= issued_at)
    AND (revoked_at IS NULL OR revoked_at >= issued_at)
  )
);

CREATE UNIQUE INDEX auth_personal_gate_sessions_live_client_unique
  ON kovcheg.auth_personal_gate_sessions (family_id, client_idempotency_key)
  WHERE revoked_at IS NULL;
CREATE INDEX auth_personal_gate_sessions_family_live_idx
  ON kovcheg.auth_personal_gate_sessions (family_id, expires_at, id)
  WHERE revoked_at IS NULL;
CREATE INDEX auth_personal_gate_sessions_account_live_idx
  ON kovcheg.auth_personal_gate_sessions (account_id, expires_at, id)
  WHERE revoked_at IS NULL;

COMMENT ON COLUMN kovcheg.auth_personal_gate_sessions.token_verifier IS
  'Server-computed verifier for a host-only gate cookie. Raw cookie values remain outside PostgreSQL.';
COMMENT ON COLUMN kovcheg.auth_personal_gate_sessions.client_idempotency_key IS
  'Opaque client activation identifier; it must not contain contact or authentication material.';

ALTER TABLE kovcheg.auth_email_challenges
  ADD COLUMN gate_session_id uuid
    REFERENCES kovcheg.auth_personal_gate_sessions (id) ON DELETE SET NULL;
ALTER TABLE kovcheg.auth_sessions
  ADD COLUMN source_challenge_id uuid
    REFERENCES kovcheg.auth_email_challenges (id) ON DELETE SET NULL;

CREATE UNIQUE INDEX auth_sessions_source_challenge_unique
  ON kovcheg.auth_sessions (source_challenge_id)
  WHERE source_challenge_id IS NOT NULL;

CREATE FUNCTION kovcheg.auth_personal_gate_audit(
  p_correlation_id varchar,
  p_actor_account_id uuid,
  p_action varchar,
  p_target_type varchar,
  p_target_id uuid,
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
    p_target_type,
    p_target_id,
    'success',
    p_details
  );
END;
$$;

CREATE FUNCTION kovcheg.admin_issue_auth_personal_gate(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_family_id uuid,
  p_code_verifier text,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  target_status kovcheg.account_status;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  IF p_code_verifier IS NULL
    OR p_code_verifier !~ '^[A-Za-z0-9_-]{43}$'
  THEN
    RAISE EXCEPTION 'invalid personal gate verifier' USING ERRCODE = '23514';
  END IF;

  SELECT account.status
  INTO target_status
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.account_id = p_account_id
  FOR UPDATE OF profile, account;

  IF NOT FOUND OR target_status <> 'active' THEN
    RAISE EXCEPTION 'active auth account target not found' USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO kovcheg.auth_personal_gate_families (
    id,
    account_id,
    code_verifier,
    issued_at
  ) VALUES (
    p_family_id,
    p_account_id,
    p_code_verifier,
    p_now
  );

  PERFORM kovcheg.auth_personal_gate_audit(
    p_correlation_id,
    actor_account_id,
    'auth.personal-gate.issued',
    'auth_personal_gate_family',
    p_family_id,
    pg_catalog.jsonb_build_object('familyStatus', 'active')
  );

  RETURN p_family_id;
END;
$$;

CREATE FUNCTION kovcheg.admin_reissue_auth_personal_gate(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_family_id uuid,
  p_code_verifier text,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  family_id uuid,
  revoked_gate_session_count integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  previous_family_id uuid;
  target_status kovcheg.account_status;
  revoked_count integer := 0;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  IF p_code_verifier IS NULL
    OR p_code_verifier !~ '^[A-Za-z0-9_-]{43}$'
  THEN
    RAISE EXCEPTION 'invalid personal gate verifier' USING ERRCODE = '23514';
  END IF;

  SELECT account.status
  INTO target_status
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.account_id = p_account_id
  FOR UPDATE OF profile, account;

  IF NOT FOUND OR target_status <> 'active' THEN
    RAISE EXCEPTION 'active auth account target not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT family.id
  INTO previous_family_id
  FROM kovcheg.auth_personal_gate_families AS family
  WHERE family.account_id = p_account_id
    AND family.status IN ('active', 'suspended')
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'current personal gate family not found' USING ERRCODE = 'P0002';
  END IF;

  UPDATE kovcheg.auth_personal_gate_families AS family
  SET status = 'revoked',
      revoked_at = GREATEST(p_now, family.issued_at),
      paused_until = NULL
  WHERE family.id = previous_family_id;

  UPDATE kovcheg.auth_personal_gate_sessions AS gate_session
  SET revoked_at = GREATEST(p_now, gate_session.issued_at)
  WHERE gate_session.family_id = previous_family_id
    AND gate_session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_count = ROW_COUNT;

  INSERT INTO kovcheg.auth_personal_gate_families (
    id,
    account_id,
    code_verifier,
    issued_at
  ) VALUES (
    p_family_id,
    p_account_id,
    p_code_verifier,
    p_now
  );

  PERFORM kovcheg.auth_personal_gate_audit(
    p_correlation_id,
    actor_account_id,
    'auth.personal-gate.reissued',
    'auth_personal_gate_family',
    p_family_id,
    pg_catalog.jsonb_build_object(
      'previousFamilyId', previous_family_id,
      'revokedGateSessionCount', revoked_count,
      'applicationSessionsRevoked', false
    )
  );

  family_id := p_family_id;
  revoked_gate_session_count := revoked_count;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION kovcheg.admin_revoke_auth_personal_gate(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_family_id uuid,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  revoked_count integer := 0;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  PERFORM 1
  FROM kovcheg.auth_personal_gate_families AS family
  WHERE family.id = p_family_id
    AND family.account_id = p_account_id
    AND family.status IN ('active', 'suspended')
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'current personal gate family not found' USING ERRCODE = 'P0002';
  END IF;

  UPDATE kovcheg.auth_personal_gate_families AS family
  SET status = 'revoked',
      revoked_at = GREATEST(p_now, family.issued_at),
      paused_until = NULL
  WHERE family.id = p_family_id;

  UPDATE kovcheg.auth_personal_gate_sessions AS gate_session
  SET revoked_at = GREATEST(p_now, gate_session.issued_at)
  WHERE gate_session.family_id = p_family_id
    AND gate_session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_count = ROW_COUNT;

  PERFORM kovcheg.auth_personal_gate_audit(
    p_correlation_id,
    actor_account_id,
    'auth.personal-gate.revoked',
    'auth_personal_gate_family',
    p_family_id,
    pg_catalog.jsonb_build_object('revokedGateSessionCount', revoked_count)
  );

  RETURN revoked_count;
END;
$$;

CREATE FUNCTION kovcheg.admin_resume_auth_personal_gate(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_family_id uuid,
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
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  PERFORM 1
  FROM kovcheg.auth_personal_gate_families AS family
  JOIN kovcheg.accounts AS account ON account.id = family.account_id
  WHERE family.id = p_family_id
    AND family.account_id = p_account_id
    AND family.status = 'suspended'
    AND account.status = 'active'
  FOR UPDATE OF family, account;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'suspended personal gate family not found' USING ERRCODE = 'P0002';
  END IF;

  UPDATE kovcheg.auth_personal_gate_families AS family
  SET status = 'active',
      suspended_at = NULL,
      mismatch_window_started_at = NULL,
      mismatch_count = 0,
      pause_window_started_at = NULL,
      pause_count = 0,
      paused_until = NULL
  WHERE family.id = p_family_id;

  PERFORM kovcheg.auth_personal_gate_audit(
    p_correlation_id,
    actor_account_id,
    'auth.personal-gate.resumed',
    'auth_personal_gate_family',
    p_family_id,
    pg_catalog.jsonb_build_object('familyStatus', 'active')
  );

  RETURN true;
END;
$$;

CREATE FUNCTION kovcheg.activate_auth_personal_gate(
  p_code_verifier text,
  p_gate_session_id uuid,
  p_gate_token_verifier text,
  p_client_idempotency_key text,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  outcome varchar,
  account_id uuid,
  family_id uuid,
  gate_session_id uuid,
  reused boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  matched_family record;
  existing_session kovcheg.auth_personal_gate_sessions%ROWTYPE;
BEGIN
  IF p_code_verifier IS NULL
    OR p_code_verifier !~ '^[A-Za-z0-9_-]{43}$'
    OR p_gate_token_verifier IS NULL
    OR p_gate_token_verifier !~ '^[A-Za-z0-9_-]{43}$'
    OR p_client_idempotency_key IS NULL
    OR p_client_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
    OR p_now IS NULL
  THEN
    RAISE EXCEPTION 'invalid personal gate activation input' USING ERRCODE = '23514';
  END IF;

  SELECT family.id, family.account_id
  INTO matched_family
  FROM kovcheg.auth_personal_gate_families AS family
  JOIN kovcheg.accounts AS account ON account.id = family.account_id
  WHERE family.code_verifier = p_code_verifier
    AND family.status = 'active'
    AND account.status = 'active'
    AND p_now >= family.issued_at
  FOR UPDATE OF family, account;

  IF NOT FOUND THEN
    outcome := 'invalid';
    RETURN NEXT;
    RETURN;
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      matched_family.id::text || ':' || p_client_idempotency_key,
      0
    )
  );

  SELECT *
  INTO existing_session
  FROM kovcheg.auth_personal_gate_sessions AS gate_session
  WHERE gate_session.family_id = matched_family.id
    AND gate_session.client_idempotency_key = p_client_idempotency_key
    AND gate_session.revoked_at IS NULL
  FOR UPDATE;

  IF FOUND AND p_now < existing_session.expires_at THEN
    IF existing_session.id <> p_gate_session_id
      OR existing_session.token_verifier <> p_gate_token_verifier
    THEN
      RAISE EXCEPTION 'personal gate activation idempotency conflict'
        USING ERRCODE = '23505';
    END IF;

    outcome := 'active';
    account_id := existing_session.account_id;
    family_id := existing_session.family_id;
    gate_session_id := existing_session.id;
    reused := true;
    RETURN NEXT;
    RETURN;
  ELSIF FOUND THEN
    UPDATE kovcheg.auth_personal_gate_sessions AS gate_session
    SET revoked_at = GREATEST(p_now, gate_session.issued_at)
    WHERE gate_session.id = existing_session.id;
  END IF;

  INSERT INTO kovcheg.auth_personal_gate_sessions (
    id,
    family_id,
    account_id,
    token_verifier,
    client_idempotency_key,
    issued_at,
    expires_at
  ) VALUES (
    p_gate_session_id,
    matched_family.id,
    matched_family.account_id,
    p_gate_token_verifier,
    p_client_idempotency_key,
    p_now,
    p_now + interval '7 days'
  );

  PERFORM kovcheg.auth_personal_gate_audit(
    p_correlation_id,
    NULL,
    'auth.personal-gate.activated',
    'auth_personal_gate_family',
    matched_family.id,
    pg_catalog.jsonb_build_object(
      'gateSessionId', p_gate_session_id,
      'reusedActivation', false
    )
  );

  outcome := 'active';
  account_id := matched_family.account_id;
  family_id := matched_family.id;
  gate_session_id := p_gate_session_id;
  reused := false;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION kovcheg.validate_auth_personal_gate_session(
  p_gate_token_verifier text,
  p_now timestamptz
)
RETURNS TABLE (
  account_id uuid,
  family_id uuid,
  gate_session_id uuid,
  email_submission_allowed boolean,
  paused_until timestamptz,
  expires_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT
    gate_session.account_id,
    gate_session.family_id,
    gate_session.id,
    family.paused_until IS NULL OR p_now >= family.paused_until,
    family.paused_until,
    gate_session.expires_at
  FROM kovcheg.auth_personal_gate_sessions AS gate_session
  JOIN kovcheg.auth_personal_gate_families AS family
    ON family.id = gate_session.family_id
    AND family.account_id = gate_session.account_id
  JOIN kovcheg.accounts AS account ON account.id = gate_session.account_id
  WHERE gate_session.token_verifier = p_gate_token_verifier
    AND gate_session.revoked_at IS NULL
    AND p_now >= gate_session.issued_at
    AND p_now < gate_session.expires_at
    AND family.status = 'active'
    AND account.status = 'active';
$$;

CREATE FUNCTION kovcheg.issue_auth_challenge_for_personal_gate(
  p_gate_token_verifier text,
  p_submitted_email text,
  p_challenge_id uuid,
  p_code_verifier text,
  p_issued_at timestamptz,
  p_expires_at timestamptz,
  p_max_attempts integer,
  p_resend_cooldown interval,
  p_correlation_id varchar
)
RETURNS TABLE (
  outcome varchar,
  account_id uuid,
  challenge_id uuid,
  recipient varchar
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  normalized_email text;
  gate_record record;
  latest_issued_at timestamptz;
  next_mismatch_count integer;
  next_pause_count integer;
  next_pause_window_started_at timestamptz;
  revoked_gate_session_count integer := 0;
BEGIN
  IF p_gate_token_verifier IS NULL
    OR p_gate_token_verifier !~ '^[A-Za-z0-9_-]{43}$'
    OR p_code_verifier IS NULL
    OR p_code_verifier !~ '^[A-Za-z0-9_-]{43}$'
    OR p_issued_at IS NULL
    OR p_expires_at IS NULL
    OR p_expires_at <= p_issued_at
    OR p_expires_at > p_issued_at + interval '10 minutes'
    OR p_max_attempts <> 5
    OR p_resend_cooldown < interval '0 seconds'
    OR p_correlation_id IS NULL
    OR p_correlation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  THEN
    RAISE EXCEPTION 'invalid gated challenge input' USING ERRCODE = '23514';
  END IF;

  SELECT
    gate_session.id AS gate_session_id,
    gate_session.account_id,
    family.id AS family_id,
    family.issued_at AS family_issued_at,
    family.paused_until,
    family.mismatch_window_started_at,
    family.mismatch_count,
    family.pause_window_started_at,
    family.pause_count,
    profile.email
  INTO gate_record
  FROM kovcheg.auth_personal_gate_sessions AS gate_session
  JOIN kovcheg.auth_personal_gate_families AS family
    ON family.id = gate_session.family_id
    AND family.account_id = gate_session.account_id
  JOIN kovcheg.account_auth_profiles AS profile
    ON profile.account_id = gate_session.account_id
  JOIN kovcheg.accounts AS account ON account.id = gate_session.account_id
  WHERE gate_session.token_verifier = p_gate_token_verifier
    AND gate_session.revoked_at IS NULL
    AND p_issued_at >= gate_session.issued_at
    AND p_issued_at < gate_session.expires_at
    AND family.status = 'active'
    AND account.status = 'active'
  FOR UPDATE OF gate_session, family, profile, account;

  IF NOT FOUND THEN
    outcome := 'invalid';
    RETURN NEXT;
    RETURN;
  END IF;

  IF gate_record.paused_until IS NOT NULL
    AND p_issued_at < gate_record.paused_until
  THEN
    outcome := 'paused';
    RETURN NEXT;
    RETURN;
  END IF;

  normalized_email := pg_catalog.lower(pg_catalog.btrim(p_submitted_email));

  IF normalized_email IS NULL OR normalized_email <> gate_record.email THEN
    IF gate_record.mismatch_window_started_at IS NULL
      OR p_issued_at >= gate_record.mismatch_window_started_at + interval '15 minutes'
    THEN
      next_mismatch_count := 1;
      gate_record.mismatch_window_started_at := p_issued_at;
    ELSE
      next_mismatch_count := gate_record.mismatch_count + 1;
    END IF;

    IF next_mismatch_count < 5 THEN
      UPDATE kovcheg.auth_personal_gate_families AS family
      SET mismatch_window_started_at = gate_record.mismatch_window_started_at,
          mismatch_count = next_mismatch_count,
          paused_until = NULL
      WHERE family.id = gate_record.family_id;

      outcome := 'mismatch';
      RETURN NEXT;
      RETURN;
    END IF;

    IF gate_record.pause_window_started_at IS NULL
      OR p_issued_at >= gate_record.pause_window_started_at + interval '24 hours'
    THEN
      next_pause_count := 1;
      next_pause_window_started_at := p_issued_at;
    ELSE
      next_pause_count := gate_record.pause_count + 1;
      next_pause_window_started_at := gate_record.pause_window_started_at;
    END IF;

    IF next_pause_count >= 3 THEN
      UPDATE kovcheg.auth_personal_gate_families AS family
      SET status = 'suspended',
          suspended_at = p_issued_at,
          mismatch_window_started_at = NULL,
          mismatch_count = 0,
          pause_window_started_at = next_pause_window_started_at,
          pause_count = 3,
          paused_until = NULL
      WHERE family.id = gate_record.family_id;

      UPDATE kovcheg.auth_personal_gate_sessions AS gate_session
      SET revoked_at = GREATEST(p_issued_at, gate_session.issued_at)
      WHERE gate_session.family_id = gate_record.family_id
        AND gate_session.revoked_at IS NULL;
      GET DIAGNOSTICS revoked_gate_session_count = ROW_COUNT;

      PERFORM kovcheg.auth_personal_gate_audit(
        p_correlation_id,
        NULL,
        'auth.personal-gate.suspended',
        'auth_personal_gate_family',
        gate_record.family_id,
        pg_catalog.jsonb_build_object(
          'pauseCount', 3,
          'revokedGateSessionCount', revoked_gate_session_count
        )
      );

      outcome := 'suspended';
      RETURN NEXT;
      RETURN;
    END IF;

    UPDATE kovcheg.auth_personal_gate_families AS family
    SET mismatch_window_started_at = NULL,
        mismatch_count = 0,
        pause_window_started_at = next_pause_window_started_at,
        pause_count = next_pause_count,
        paused_until = p_issued_at + interval '15 minutes'
    WHERE family.id = gate_record.family_id;

    PERFORM kovcheg.auth_personal_gate_audit(
      p_correlation_id,
      NULL,
      'auth.personal-gate.paused',
      'auth_personal_gate_family',
      gate_record.family_id,
      pg_catalog.jsonb_build_object('pauseCount', next_pause_count)
    );

    outcome := 'paused';
    RETURN NEXT;
    RETURN;
  END IF;

  UPDATE kovcheg.auth_personal_gate_families AS family
  SET mismatch_window_started_at = NULL,
      mismatch_count = 0,
      paused_until = NULL
  WHERE family.id = gate_record.family_id;

  SELECT challenge.issued_at
  INTO latest_issued_at
  FROM kovcheg.auth_email_challenges AS challenge
  WHERE challenge.account_id = gate_record.account_id
  ORDER BY challenge.issued_at DESC
  LIMIT 1;

  IF latest_issued_at IS NOT NULL
    AND p_issued_at - latest_issued_at < p_resend_cooldown
  THEN
    outcome := 'rate_limited';
    RETURN NEXT;
    RETURN;
  END IF;

  UPDATE kovcheg.auth_email_challenges AS challenge
  SET invalidated_at = p_issued_at
  WHERE challenge.account_id = gate_record.account_id
    AND challenge.used_at IS NULL
    AND challenge.invalidated_at IS NULL;

  INSERT INTO kovcheg.auth_email_challenges (
    id,
    account_id,
    code_verifier,
    issued_at,
    expires_at,
    max_attempts,
    gate_session_id
  ) VALUES (
    p_challenge_id,
    gate_record.account_id,
    p_code_verifier,
    p_issued_at,
    p_expires_at,
    p_max_attempts,
    gate_record.gate_session_id
  );

  outcome := 'issued';
  account_id := gate_record.account_id;
  challenge_id := p_challenge_id;
  recipient := gate_record.email;
  RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION kovcheg.consume_auth_challenge_and_create_session(
  p_challenge_id uuid,
  p_candidate_code_verifier text,
  p_now timestamptz,
  p_session_id uuid,
  p_session_token_verifier text,
  p_session_issued_at timestamptz,
  p_idle_lifetime_ms bigint,
  p_absolute_expires_at timestamptz
)
RETURNS TABLE (
  outcome varchar,
  account_id uuid,
  session_id uuid,
  auth_roles kovcheg.auth_account_role[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  challenge_record kovcheg.auth_email_challenges%ROWTYPE;
  matched_role kovcheg.auth_account_role;
  matched_status kovcheg.account_status;
  initial_idle_expires_at timestamptz;
BEGIN
  SELECT *
  INTO challenge_record
  FROM kovcheg.auth_email_challenges
  WHERE id = p_challenge_id
  FOR UPDATE;

  IF NOT FOUND
    OR challenge_record.invalidated_at IS NOT NULL
    OR challenge_record.used_at IS NOT NULL
    OR p_now >= challenge_record.expires_at
    OR challenge_record.attempt_count >= challenge_record.max_attempts
  THEN
    outcome := 'invalid';
    RETURN NEXT;
    RETURN;
  END IF;

  IF challenge_record.code_verifier <> p_candidate_code_verifier THEN
    UPDATE kovcheg.auth_email_challenges
    SET attempt_count = attempt_count + 1
    WHERE id = p_challenge_id;
    outcome := 'invalid';
    RETURN NEXT;
    RETURN;
  END IF;

  SELECT profile.auth_role, account.status
  INTO matched_role, matched_status
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.account_id = challenge_record.account_id
  FOR UPDATE OF profile, account;

  IF NOT FOUND OR matched_status <> 'active' THEN
    UPDATE kovcheg.auth_email_challenges
    SET invalidated_at = p_now
    WHERE id = p_challenge_id;
    outcome := 'invalid';
    RETURN NEXT;
    RETURN;
  END IF;

  initial_idle_expires_at := LEAST(
    p_absolute_expires_at,
    p_session_issued_at + (p_idle_lifetime_ms * interval '1 millisecond')
  );

  INSERT INTO kovcheg.auth_sessions (
    id,
    account_id,
    token_verifier,
    issued_at,
    last_seen_at,
    idle_lifetime_ms,
    idle_expires_at,
    absolute_expires_at,
    source_challenge_id
  ) VALUES (
    p_session_id,
    challenge_record.account_id,
    p_session_token_verifier,
    p_session_issued_at,
    p_session_issued_at,
    p_idle_lifetime_ms,
    initial_idle_expires_at,
    p_absolute_expires_at,
    challenge_record.id
  );

  UPDATE kovcheg.auth_email_challenges
  SET used_at = p_now
  WHERE id = p_challenge_id;

  outcome := 'authenticated';
  account_id := challenge_record.account_id;
  session_id := p_session_id;
  auth_roles := ARRAY[matched_role]::kovcheg.auth_account_role[];
  RETURN NEXT;
END;
$$;

CREATE FUNCTION kovcheg.extend_auth_personal_gate_after_login(
  p_gate_token_verifier text,
  p_application_session_verifier text,
  p_now timestamptz
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  gate_session_record kovcheg.auth_personal_gate_sessions%ROWTYPE;
  application_session_record kovcheg.auth_sessions%ROWTYPE;
  challenge_gate_session_id uuid;
  family_status kovcheg.auth_personal_gate_family_status;
  account_status kovcheg.account_status;
  new_expires_at timestamptz;
BEGIN
  SELECT *
  INTO gate_session_record
  FROM kovcheg.auth_personal_gate_sessions AS gate_session
  WHERE gate_session.token_verifier = p_gate_token_verifier
  FOR UPDATE;

  IF NOT FOUND
    OR gate_session_record.revoked_at IS NOT NULL
    OR p_now < gate_session_record.issued_at
    OR p_now >= gate_session_record.expires_at
  THEN
    RETURN NULL;
  END IF;

  SELECT *
  INTO application_session_record
  FROM kovcheg.auth_sessions AS session
  WHERE session.token_verifier = p_application_session_verifier
  FOR UPDATE;

  IF NOT FOUND
    OR application_session_record.account_id <> gate_session_record.account_id
    OR application_session_record.revoked_at IS NOT NULL
    OR p_now < application_session_record.issued_at
    OR p_now >= application_session_record.idle_expires_at
    OR p_now >= application_session_record.absolute_expires_at
  THEN
    RETURN NULL;
  END IF;

  SELECT challenge.gate_session_id
  INTO challenge_gate_session_id
  FROM kovcheg.auth_email_challenges AS challenge
  WHERE challenge.id = application_session_record.source_challenge_id
  FOR UPDATE;

  IF NOT FOUND OR challenge_gate_session_id <> gate_session_record.id THEN
    RETURN NULL;
  END IF;

  SELECT family.status, account.status
  INTO family_status, account_status
  FROM kovcheg.auth_personal_gate_families AS family
  JOIN kovcheg.accounts AS account ON account.id = family.account_id
  WHERE family.id = gate_session_record.family_id
    AND family.account_id = gate_session_record.account_id
  FOR UPDATE OF family, account;

  IF NOT FOUND OR family_status <> 'active' OR account_status <> 'active' THEN
    RETURN NULL;
  END IF;

  new_expires_at := p_now + interval '7 days';
  UPDATE kovcheg.auth_personal_gate_sessions AS gate_session
  SET last_login_at = p_now,
      expires_at = new_expires_at
  WHERE gate_session.id = gate_session_record.id;

  RETURN new_expires_at;
END;
$$;

CREATE FUNCTION kovcheg.admin_security_reset_auth_access(
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

CREATE FUNCTION kovcheg.revoke_auth_personal_gate_on_account_deactivation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  effective_time timestamptz;
BEGIN
  IF NEW.status = 'deactivated' AND OLD.status IS DISTINCT FROM NEW.status THEN
    effective_time := COALESCE(NEW.deactivated_at, pg_catalog.clock_timestamp());

    UPDATE kovcheg.auth_personal_gate_families AS family
    SET status = 'revoked',
        revoked_at = GREATEST(effective_time, family.issued_at),
        paused_until = NULL
    WHERE family.account_id = NEW.id
      AND family.status IN ('active', 'suspended');

    UPDATE kovcheg.auth_personal_gate_sessions AS gate_session
    SET revoked_at = GREATEST(effective_time, gate_session.issued_at)
    WHERE gate_session.account_id = NEW.id
      AND gate_session.revoked_at IS NULL;

    UPDATE kovcheg.auth_email_challenges AS challenge
    SET invalidated_at = GREATEST(effective_time, challenge.issued_at)
    WHERE challenge.account_id = NEW.id
      AND challenge.used_at IS NULL
      AND challenge.invalidated_at IS NULL;

    UPDATE kovcheg.auth_sessions AS session
    SET revoked_at = GREATEST(effective_time, session.issued_at)
    WHERE session.account_id = NEW.id
      AND session.revoked_at IS NULL;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER accounts_revoke_personal_gate_on_deactivation
AFTER UPDATE OF status ON kovcheg.accounts
FOR EACH ROW EXECUTE FUNCTION kovcheg.revoke_auth_personal_gate_on_account_deactivation();

REVOKE ALL ON ALL TABLES IN SCHEMA kovcheg FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA kovcheg FROM PUBLIC;

REVOKE ALL ON FUNCTION kovcheg.auth_personal_gate_audit(
  varchar, uuid, varchar, varchar, uuid, jsonb
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_issue_auth_personal_gate(
  text, uuid, uuid, text, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_reissue_auth_personal_gate(
  text, uuid, uuid, text, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_revoke_auth_personal_gate(
  text, uuid, uuid, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_resume_auth_personal_gate(
  text, uuid, uuid, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.activate_auth_personal_gate(
  text, uuid, text, text, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.validate_auth_personal_gate_session(
  text, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.issue_auth_challenge_for_personal_gate(
  text, text, uuid, text, timestamptz, timestamptz, integer, interval, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.extend_auth_personal_gate_after_login(
  text, text, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_security_reset_auth_access(
  text, uuid, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.revoke_auth_personal_gate_on_account_deactivation()
FROM PUBLIC;

GRANT USAGE ON TYPE kovcheg.auth_personal_gate_family_status
TO kovcheg_auth_runtime;

GRANT EXECUTE ON FUNCTION
  kovcheg.admin_issue_auth_personal_gate(
    text, uuid, uuid, text, timestamptz, varchar
  ),
  kovcheg.admin_reissue_auth_personal_gate(
    text, uuid, uuid, text, timestamptz, varchar
  ),
  kovcheg.admin_revoke_auth_personal_gate(
    text, uuid, uuid, timestamptz, varchar
  ),
  kovcheg.admin_resume_auth_personal_gate(
    text, uuid, uuid, timestamptz, varchar
  ),
  kovcheg.activate_auth_personal_gate(
    text, uuid, text, text, timestamptz, varchar
  ),
  kovcheg.validate_auth_personal_gate_session(text, timestamptz),
  kovcheg.issue_auth_challenge_for_personal_gate(
    text, text, uuid, text, timestamptz, timestamptz, integer, interval, varchar
  ),
  kovcheg.extend_auth_personal_gate_after_login(text, text, timestamptz),
  kovcheg.admin_security_reset_auth_access(text, uuid, timestamptz, varchar)
TO kovcheg_auth_runtime;

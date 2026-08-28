ALTER TABLE kovcheg.auth_sessions
  ADD COLUMN source_oidc_token_verifier varchar(43),
  ADD CONSTRAINT auth_sessions_source_oidc_token_verifier_check CHECK (
    source_oidc_token_verifier IS NULL
    OR source_oidc_token_verifier ~ '^[A-Za-z0-9_-]{43}$'
  ),
  ADD CONSTRAINT auth_sessions_source_oidc_token_verifier_unique
    UNIQUE (source_oidc_token_verifier);

COMMENT ON COLUMN kovcheg.auth_sessions.source_oidc_token_verifier IS
  'One-way verifier for the provider access token consumed by a first-party OIDC application-session bridge. Raw tokens remain outside PostgreSQL.';

CREATE FUNCTION kovcheg.create_oidc_application_session(
  p_account_id uuid,
  p_source_token_verifier text,
  p_session_id uuid,
  p_session_token_verifier text,
  p_session_issued_at timestamptz,
  p_idle_lifetime_ms bigint,
  p_absolute_expires_at timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (outcome varchar)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  inserted_session_id uuid;
  initial_idle_expires_at timestamptz;
  migration_version text;
BEGIN
  IF p_account_id IS NULL
    OR p_source_token_verifier IS NULL
    OR p_source_token_verifier !~ '^[A-Za-z0-9_-]{43}$'
    OR p_session_id IS NULL
    OR p_session_token_verifier IS NULL
    OR p_session_token_verifier !~ '^[A-Za-z0-9_-]{43}$'
    OR p_session_issued_at IS NULL
    OR p_idle_lifetime_ms IS NULL
    OR p_idle_lifetime_ms <= 0
    OR p_absolute_expires_at IS NULL
    OR p_absolute_expires_at <= p_session_issued_at
    OR p_correlation_id IS NULL
    OR p_correlation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  THEN
    RAISE EXCEPTION 'invalid OIDC application session input' USING ERRCODE = '23514';
  END IF;

  PERFORM 1
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.account_id = p_account_id
    AND account.status = 'active'
  FOR UPDATE OF profile, account;

  IF NOT FOUND THEN
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
    source_oidc_token_verifier
  ) VALUES (
    p_session_id,
    p_account_id,
    p_session_token_verifier,
    p_session_issued_at,
    p_session_issued_at,
    p_idle_lifetime_ms,
    initial_idle_expires_at,
    p_absolute_expires_at,
    p_source_token_verifier
  )
  ON CONFLICT (source_oidc_token_verifier) DO NOTHING
  RETURNING id INTO inserted_session_id;

  IF inserted_session_id IS NULL THEN
    outcome := 'invalid';
    RETURN NEXT;
    RETURN;
  END IF;

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    p_account_id,
    'auth.oidc.application-session.created',
    'auth_session',
    inserted_session_id,
    'success',
    '{}'::jsonb
  );

  outcome := 'authenticated';
  RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION kovcheg.create_oidc_application_session(
  uuid, text, uuid, text, timestamptz, bigint, timestamptz, varchar
) IS
  'Creates one bounded application session for an existing active account after the Auth service validates a first-party OIDC access token. A token verifier is accepted at most once.';

REVOKE ALL ON FUNCTION kovcheg.create_oidc_application_session(
  uuid, text, uuid, text, timestamptz, bigint, timestamptz, varchar
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION kovcheg.create_oidc_application_session(
  uuid, text, uuid, text, timestamptz, bigint, timestamptz, varchar
) TO kovcheg_auth_runtime;

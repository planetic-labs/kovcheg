CREATE TYPE kovcheg.auth_account_role AS ENUM ('administrator', 'student');
CREATE TYPE kovcheg.oidc_token_endpoint_auth_method AS ENUM ('none', 'client_secret_basic');

CREATE TABLE kovcheg.account_auth_profiles (
  account_id uuid PRIMARY KEY REFERENCES kovcheg.accounts (id) ON DELETE CASCADE,
  email varchar(254) NOT NULL UNIQUE,
  display_name varchar(120) NOT NULL,
  auth_role kovcheg.auth_account_role NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT account_auth_profiles_email_normalized_check CHECK (
    email = pg_catalog.lower(pg_catalog.btrim(email))
    AND email ~ '^[^[:space:]@]+@[^[:space:]@]+$'
  ),
  CONSTRAINT account_auth_profiles_display_name_check CHECK (
    display_name = pg_catalog.btrim(display_name)
    AND char_length(display_name) BETWEEN 1 AND 120
  ),
  CONSTRAINT account_auth_profiles_updated_at_check CHECK (updated_at >= created_at)
);

COMMENT ON COLUMN kovcheg.account_auth_profiles.email IS
  'Normalized runtime contact identity. Values must never appear in migrations, fixtures, logs, audit details, or operation metadata.';

CREATE TABLE kovcheg.auth_administrator_bootstraps (
  bootstrap_id varchar(200) PRIMARY KEY,
  account_id uuid NOT NULL UNIQUE
    REFERENCES kovcheg.account_auth_profiles (account_id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT auth_administrator_bootstraps_id_check CHECK (
    bootstrap_id = pg_catalog.btrim(bootstrap_id)
    AND char_length(bootstrap_id) BETWEEN 16 AND 200
  )
);

CREATE TABLE kovcheg.auth_email_challenges (
  id uuid PRIMARY KEY,
  account_id uuid NOT NULL
    REFERENCES kovcheg.account_auth_profiles (account_id) ON DELETE CASCADE,
  code_verifier varchar(43) NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  invalidated_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0,
  max_attempts integer NOT NULL,
  CONSTRAINT auth_email_challenges_verifier_check CHECK (
    code_verifier ~ '^[A-Za-z0-9_-]{43}$'
  ),
  CONSTRAINT auth_email_challenges_expiry_check CHECK (expires_at > issued_at),
  CONSTRAINT auth_email_challenges_attempts_check CHECK (
    max_attempts BETWEEN 1 AND 100
    AND attempt_count BETWEEN 0 AND max_attempts
  ),
  CONSTRAINT auth_email_challenges_terminal_state_check CHECK (
    NOT (used_at IS NOT NULL AND invalidated_at IS NOT NULL)
    AND (used_at IS NULL OR (used_at >= issued_at AND used_at < expires_at))
    AND (invalidated_at IS NULL OR invalidated_at >= issued_at)
  )
);

CREATE UNIQUE INDEX auth_email_challenges_one_open_per_account_unique
  ON kovcheg.auth_email_challenges (account_id)
  WHERE used_at IS NULL AND invalidated_at IS NULL;
CREATE INDEX auth_email_challenges_account_issued_idx
  ON kovcheg.auth_email_challenges (account_id, issued_at DESC);
CREATE INDEX auth_email_challenges_expiry_idx
  ON kovcheg.auth_email_challenges (expires_at, id)
  WHERE used_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE kovcheg.auth_sessions (
  id uuid PRIMARY KEY,
  account_id uuid NOT NULL
    REFERENCES kovcheg.account_auth_profiles (account_id) ON DELETE CASCADE,
  token_verifier varchar(43) NOT NULL UNIQUE,
  issued_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  idle_lifetime_ms bigint NOT NULL,
  idle_expires_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CONSTRAINT auth_sessions_verifier_check CHECK (
    token_verifier ~ '^[A-Za-z0-9_-]{43}$'
  ),
  CONSTRAINT auth_sessions_lifetime_check CHECK (
    idle_lifetime_ms > 0
    AND absolute_expires_at > issued_at
    AND last_seen_at >= issued_at
    AND idle_expires_at > issued_at
    AND idle_expires_at <= absolute_expires_at
  ),
  CONSTRAINT auth_sessions_revocation_check CHECK (
    revoked_at IS NULL OR revoked_at >= issued_at
  )
);

CREATE INDEX auth_sessions_account_live_idx
  ON kovcheg.auth_sessions (account_id, absolute_expires_at, idle_expires_at)
  WHERE revoked_at IS NULL;
CREATE INDEX auth_sessions_expiry_idx
  ON kovcheg.auth_sessions (LEAST(idle_expires_at, absolute_expires_at), id)
  WHERE revoked_at IS NULL;

CREATE TABLE kovcheg.oidc_clients (
  client_id varchar(128) PRIMARY KEY,
  allowed_scope varchar(16) NOT NULL DEFAULT 'openid',
  grant_type varchar(32) NOT NULL DEFAULT 'authorization_code',
  pkce_required boolean NOT NULL DEFAULT true,
  token_endpoint_auth_method kovcheg.oidc_token_endpoint_auth_method NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT oidc_clients_id_check CHECK (
    client_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$'
  ),
  CONSTRAINT oidc_clients_scope_check CHECK (allowed_scope = 'openid'),
  CONSTRAINT oidc_clients_grant_check CHECK (grant_type = 'authorization_code'),
  CONSTRAINT oidc_clients_pkce_check CHECK (pkce_required)
);

CREATE TABLE kovcheg.oidc_client_redirect_uris (
  client_id varchar(128) NOT NULL REFERENCES kovcheg.oidc_clients (client_id) ON DELETE CASCADE,
  redirect_uri varchar(2048) NOT NULL,
  PRIMARY KEY (client_id, redirect_uri),
  CONSTRAINT oidc_client_redirect_uris_exact_check CHECK (
    redirect_uri = pg_catalog.btrim(redirect_uri)
    AND redirect_uri ~ '^https?://[^[:space:]]+$'
    AND pg_catalog.strpos(redirect_uri, '*') = 0
  )
);

CREATE FUNCTION kovcheg.reject_oidc_client_id_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.client_id IS DISTINCT FROM OLD.client_id THEN
    RAISE EXCEPTION 'OIDC client ID is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.reject_oidc_client_id_update() FROM PUBLIC;

CREATE TRIGGER oidc_clients_reject_id_update
BEFORE UPDATE OF client_id ON kovcheg.oidc_clients
FOR EACH ROW EXECUTE FUNCTION kovcheg.reject_oidc_client_id_update();

CREATE TABLE kovcheg.oidc_provider_artifacts (
  model varchar(64) NOT NULL,
  artifact_id varchar(256) NOT NULL,
  payload jsonb NOT NULL,
  grant_id varchar(256),
  user_code varchar(256),
  uid varchar(256),
  consumed_at timestamptz,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (model, artifact_id),
  CONSTRAINT oidc_provider_artifacts_model_check CHECK (
    model ~ '^[A-Za-z][A-Za-z0-9]{1,63}$'
  ),
  CONSTRAINT oidc_provider_artifacts_id_check CHECK (
    char_length(artifact_id) BETWEEN 1 AND 256
  ),
  CONSTRAINT oidc_provider_artifacts_payload_check CHECK (jsonb_typeof(payload) = 'object'),
  CONSTRAINT oidc_provider_artifacts_expiry_check CHECK (expires_at > created_at),
  CONSTRAINT oidc_provider_artifacts_consumed_check CHECK (
    consumed_at IS NULL OR consumed_at >= created_at
  ),
  CONSTRAINT oidc_provider_artifacts_updated_at_check CHECK (updated_at >= created_at)
);

COMMENT ON COLUMN kovcheg.oidc_provider_artifacts.payload IS
  'Protected oidc-provider adapter state. Signing keys, cookie keys, client secrets, auth peppers, and other secret-store inputs do not belong here.';

CREATE INDEX oidc_provider_artifacts_expiry_idx
  ON kovcheg.oidc_provider_artifacts (expires_at, model, artifact_id);
CREATE INDEX oidc_provider_artifacts_grant_idx
  ON kovcheg.oidc_provider_artifacts (grant_id, model, artifact_id)
  WHERE grant_id IS NOT NULL;
CREATE UNIQUE INDEX oidc_provider_artifacts_user_code_unique
  ON kovcheg.oidc_provider_artifacts (user_code)
  WHERE user_code IS NOT NULL;
CREATE UNIQUE INDEX oidc_provider_artifacts_uid_unique
  ON kovcheg.oidc_provider_artifacts (uid)
  WHERE uid IS NOT NULL;

CREATE FUNCTION kovcheg.find_auth_account_by_id(p_account_id uuid)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  auth_role kovcheg.auth_account_role,
  account_status kovcheg.account_status
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT
    profile.account_id,
    profile.email,
    profile.display_name,
    profile.auth_role,
    account.status
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.account_id = p_account_id;
$$;

CREATE FUNCTION kovcheg.create_auth_account(
  p_account_id uuid,
  p_email text,
  p_display_name text
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  auth_role kovcheg.auth_account_role,
  account_status kovcheg.account_status
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  normalized_email text := pg_catalog.lower(pg_catalog.btrim(p_email));
  normalized_display_name text := pg_catalog.btrim(p_display_name);
BEGIN
  PERFORM *
  FROM kovcheg.provision_account_with_starter_set(
    p_account_id,
    ('auth-account-create-' || p_account_id::text)::varchar
  );

  INSERT INTO kovcheg.account_auth_profiles (
    account_id,
    email,
    display_name,
    auth_role
  ) VALUES (
    p_account_id,
    normalized_email,
    normalized_display_name,
    'student'
  );

  RETURN QUERY
  SELECT * FROM kovcheg.find_auth_account_by_id(p_account_id);
END;
$$;

CREATE FUNCTION kovcheg.bootstrap_auth_administrator(
  p_bootstrap_id text,
  p_account_id uuid,
  p_email text,
  p_display_name text
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  auth_role kovcheg.auth_account_role,
  account_status kovcheg.account_status,
  created boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  normalized_bootstrap_id text := pg_catalog.btrim(p_bootstrap_id);
  normalized_email text := pg_catalog.lower(pg_catalog.btrim(p_email));
  normalized_display_name text := pg_catalog.btrim(p_display_name);
  existing_account_id uuid;
  existing_email varchar(254);
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(normalized_bootstrap_id, 0)
  );

  SELECT bootstrap.account_id, profile.email
  INTO existing_account_id, existing_email
  FROM kovcheg.auth_administrator_bootstraps AS bootstrap
  JOIN kovcheg.account_auth_profiles AS profile ON profile.account_id = bootstrap.account_id
  WHERE bootstrap.bootstrap_id = normalized_bootstrap_id
  FOR UPDATE OF bootstrap, profile;

  IF FOUND THEN
    IF existing_account_id <> p_account_id OR existing_email <> normalized_email THEN
      RAISE EXCEPTION 'administrator bootstrap conflicts with existing binding'
        USING ERRCODE = '23505', CONSTRAINT = 'auth_administrator_bootstraps_pkey';
    END IF;

    RETURN QUERY
    SELECT
      profile.account_id,
      profile.email,
      profile.display_name,
      profile.auth_role,
      account.status,
      false
    FROM kovcheg.account_auth_profiles AS profile
    JOIN kovcheg.accounts AS account ON account.id = profile.account_id
    WHERE profile.account_id = existing_account_id;
    RETURN;
  END IF;

  PERFORM *
  FROM kovcheg.provision_account_with_starter_set(
    p_account_id,
    ('auth-bootstrap-' || p_account_id::text)::varchar
  );

  INSERT INTO kovcheg.account_auth_profiles (
    account_id,
    email,
    display_name,
    auth_role
  ) VALUES (
    p_account_id,
    normalized_email,
    normalized_display_name,
    'administrator'
  );

  INSERT INTO kovcheg.auth_administrator_bootstraps (bootstrap_id, account_id)
  VALUES (normalized_bootstrap_id, p_account_id);

  RETURN QUERY
  SELECT
    profile.account_id,
    profile.email,
    profile.display_name,
    profile.auth_role,
    account.status,
    true
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.account_id = p_account_id;
END;
$$;

CREATE FUNCTION kovcheg.issue_auth_challenge_for_active_account(
  p_email text,
  p_challenge_id uuid,
  p_code_verifier text,
  p_issued_at timestamptz,
  p_expires_at timestamptz,
  p_max_attempts integer,
  p_resend_cooldown interval
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
  normalized_email text := pg_catalog.lower(pg_catalog.btrim(p_email));
  matched_account_id uuid;
  matched_recipient varchar(254);
  latest_issued_at timestamptz;
BEGIN
  IF p_resend_cooldown < interval '0 seconds' THEN
    RAISE EXCEPTION 'resend cooldown must not be negative' USING ERRCODE = '23514';
  END IF;

  SELECT profile.account_id, profile.email
  INTO matched_account_id, matched_recipient
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.email = normalized_email AND account.status = 'active'
  FOR UPDATE OF profile, account;

  IF NOT FOUND THEN
    outcome := 'neutral';
    RETURN NEXT;
    RETURN;
  END IF;

  SELECT challenge.issued_at
  INTO latest_issued_at
  FROM kovcheg.auth_email_challenges AS challenge
  WHERE challenge.account_id = matched_account_id
  ORDER BY challenge.issued_at DESC
  LIMIT 1;

  IF latest_issued_at IS NOT NULL
    AND p_issued_at - latest_issued_at < p_resend_cooldown
  THEN
    outcome := 'neutral';
    RETURN NEXT;
    RETURN;
  END IF;

  UPDATE kovcheg.auth_email_challenges
  SET invalidated_at = p_issued_at
  WHERE auth_email_challenges.account_id = matched_account_id
    AND used_at IS NULL
    AND invalidated_at IS NULL;

  INSERT INTO kovcheg.auth_email_challenges (
    id,
    account_id,
    code_verifier,
    issued_at,
    expires_at,
    max_attempts
  ) VALUES (
    p_challenge_id,
    matched_account_id,
    p_code_verifier,
    p_issued_at,
    p_expires_at,
    p_max_attempts
  );

  outcome := 'issued';
  account_id := matched_account_id;
  challenge_id := p_challenge_id;
  recipient := matched_recipient;
  RETURN NEXT;
END;
$$;

CREATE FUNCTION kovcheg.consume_auth_challenge_and_create_session(
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
    absolute_expires_at
  ) VALUES (
    p_session_id,
    challenge_record.account_id,
    p_session_token_verifier,
    p_session_issued_at,
    p_session_issued_at,
    p_idle_lifetime_ms,
    initial_idle_expires_at,
    p_absolute_expires_at
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

CREATE FUNCTION kovcheg.authenticate_auth_session(
  p_token_verifier text,
  p_now timestamptz
)
RETURNS TABLE (
  account_id uuid,
  session_id uuid,
  auth_roles kovcheg.auth_account_role[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  session_record kovcheg.auth_sessions%ROWTYPE;
  matched_role kovcheg.auth_account_role;
  matched_status kovcheg.account_status;
BEGIN
  SELECT *
  INTO session_record
  FROM kovcheg.auth_sessions
  WHERE token_verifier = p_token_verifier
  FOR UPDATE;

  IF NOT FOUND OR session_record.revoked_at IS NOT NULL THEN
    RETURN;
  END IF;

  SELECT profile.auth_role, account.status
  INTO matched_role, matched_status
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.account_id = session_record.account_id
  FOR UPDATE OF profile, account;

  IF NOT FOUND
    OR matched_status <> 'active'
    OR p_now >= session_record.idle_expires_at
    OR p_now >= session_record.absolute_expires_at
  THEN
    UPDATE kovcheg.auth_sessions
    SET revoked_at = GREATEST(p_now, issued_at)
    WHERE id = session_record.id AND revoked_at IS NULL;
    RETURN;
  END IF;

  UPDATE kovcheg.auth_sessions
  SET last_seen_at = p_now,
      idle_expires_at = LEAST(
        absolute_expires_at,
        p_now + (idle_lifetime_ms * interval '1 millisecond')
      )
  WHERE id = session_record.id;

  account_id := session_record.account_id;
  session_id := session_record.id;
  auth_roles := ARRAY[matched_role]::kovcheg.auth_account_role[];
  RETURN NEXT;
END;
$$;

CREATE FUNCTION kovcheg.invalidate_auth_challenge(p_challenge_id uuid, p_now timestamptz)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  UPDATE kovcheg.auth_email_challenges
  SET invalidated_at = p_now
  WHERE id = p_challenge_id AND used_at IS NULL AND invalidated_at IS NULL;
$$;

CREATE FUNCTION kovcheg.revoke_auth_session_by_id(p_session_id uuid, p_now timestamptz)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  affected_sessions integer;
BEGIN
  UPDATE kovcheg.auth_sessions
  SET revoked_at = GREATEST(p_now, issued_at)
  WHERE id = p_session_id AND revoked_at IS NULL;
  GET DIAGNOSTICS affected_sessions = ROW_COUNT;
  RETURN affected_sessions = 1;
END;
$$;

CREATE FUNCTION kovcheg.revoke_auth_session_by_verifier(
  p_token_verifier text,
  p_now timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  affected_sessions integer;
BEGIN
  UPDATE kovcheg.auth_sessions
  SET revoked_at = GREATEST(p_now, issued_at)
  WHERE token_verifier = p_token_verifier AND revoked_at IS NULL;
  GET DIAGNOSTICS affected_sessions = ROW_COUNT;
  RETURN affected_sessions = 1;
END;
$$;

CREATE FUNCTION kovcheg.set_auth_account_status_and_revoke(
  p_account_id uuid,
  p_status kovcheg.account_status,
  p_now timestamptz
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  auth_role kovcheg.auth_account_role,
  account_status kovcheg.account_status
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  PERFORM 1
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.account_id = p_account_id
  FOR UPDATE OF profile, account;

  IF NOT FOUND THEN
    RETURN;
  END IF;

  UPDATE kovcheg.accounts
  SET status = p_status,
      activated_at = CASE
        WHEN p_status = 'active' THEN COALESCE(activated_at, p_now)
        ELSE activated_at
      END,
      deactivated_at = CASE WHEN p_status = 'deactivated' THEN p_now ELSE NULL END
  WHERE id = p_account_id;

  IF p_status = 'deactivated' THEN
    UPDATE kovcheg.auth_email_challenges
    SET invalidated_at = p_now
    WHERE auth_email_challenges.account_id = p_account_id
      AND used_at IS NULL
      AND invalidated_at IS NULL;

    UPDATE kovcheg.auth_sessions
    SET revoked_at = GREATEST(p_now, issued_at)
    WHERE auth_sessions.account_id = p_account_id AND revoked_at IS NULL;
  END IF;

  RETURN QUERY
  SELECT * FROM kovcheg.find_auth_account_by_id(p_account_id);
END;
$$;

CREATE FUNCTION kovcheg.find_registered_oidc_client(p_client_id text)
RETURNS TABLE (
  client_id varchar,
  redirect_uris varchar[],
  allowed_scope varchar,
  grant_type varchar,
  pkce_required boolean,
  token_endpoint_auth_method kovcheg.oidc_token_endpoint_auth_method
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT
    client.client_id,
    pg_catalog.array_agg(redirect.redirect_uri ORDER BY redirect.redirect_uri),
    client.allowed_scope,
    client.grant_type,
    client.pkce_required,
    client.token_endpoint_auth_method
  FROM kovcheg.oidc_clients AS client
  JOIN kovcheg.oidc_client_redirect_uris AS redirect ON redirect.client_id = client.client_id
  WHERE client.client_id = p_client_id
  GROUP BY client.client_id;
$$;

CREATE FUNCTION kovcheg.oidc_redirect_uri_is_registered(
  p_client_id text,
  p_redirect_uri text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM kovcheg.oidc_client_redirect_uris
    WHERE client_id = p_client_id AND redirect_uri = p_redirect_uri
  );
$$;

CREATE FUNCTION kovcheg.upsert_oidc_provider_artifact(
  p_model text,
  p_artifact_id text,
  p_payload jsonb,
  p_expires_at timestamptz,
  p_grant_id text DEFAULT NULL,
  p_user_code text DEFAULT NULL,
  p_uid text DEFAULT NULL
)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  INSERT INTO kovcheg.oidc_provider_artifacts (
    model,
    artifact_id,
    payload,
    expires_at,
    grant_id,
    user_code,
    uid
  ) VALUES (
    p_model,
    p_artifact_id,
    p_payload,
    p_expires_at,
    p_grant_id,
    p_user_code,
    p_uid
  )
  ON CONFLICT (model, artifact_id) DO UPDATE
  SET payload = EXCLUDED.payload,
      expires_at = EXCLUDED.expires_at,
      grant_id = EXCLUDED.grant_id,
      user_code = EXCLUDED.user_code,
      uid = EXCLUDED.uid,
      updated_at = clock_timestamp();
$$;

CREATE FUNCTION kovcheg.find_oidc_provider_artifact(
  p_model text,
  p_artifact_id text,
  p_now timestamptz
)
RETURNS TABLE (payload jsonb, consumed_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT artifact.payload, artifact.consumed_at
  FROM kovcheg.oidc_provider_artifacts AS artifact
  WHERE artifact.model = p_model
    AND artifact.artifact_id = p_artifact_id
    AND artifact.expires_at > p_now;
$$;

CREATE FUNCTION kovcheg.find_oidc_provider_artifact_by_user_code(
  p_user_code text,
  p_now timestamptz
)
RETURNS TABLE (model varchar, artifact_id varchar, payload jsonb, consumed_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT artifact.model, artifact.artifact_id, artifact.payload, artifact.consumed_at
  FROM kovcheg.oidc_provider_artifacts AS artifact
  WHERE artifact.user_code = p_user_code AND artifact.expires_at > p_now;
$$;

CREATE FUNCTION kovcheg.find_oidc_provider_artifact_by_uid(
  p_uid text,
  p_now timestamptz
)
RETURNS TABLE (model varchar, artifact_id varchar, payload jsonb, consumed_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT artifact.model, artifact.artifact_id, artifact.payload, artifact.consumed_at
  FROM kovcheg.oidc_provider_artifacts AS artifact
  WHERE artifact.uid = p_uid AND artifact.expires_at > p_now;
$$;

CREATE FUNCTION kovcheg.consume_oidc_provider_artifact(
  p_model text,
  p_artifact_id text,
  p_now timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  affected_artifacts integer;
BEGIN
  UPDATE kovcheg.oidc_provider_artifacts
  SET consumed_at = p_now,
      updated_at = clock_timestamp()
  WHERE model = p_model
    AND artifact_id = p_artifact_id
    AND expires_at > p_now
    AND consumed_at IS NULL;
  GET DIAGNOSTICS affected_artifacts = ROW_COUNT;
  RETURN affected_artifacts = 1;
END;
$$;

CREATE FUNCTION kovcheg.destroy_oidc_provider_artifact(p_model text, p_artifact_id text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  affected_artifacts integer;
BEGIN
  DELETE FROM kovcheg.oidc_provider_artifacts
  WHERE model = p_model AND artifact_id = p_artifact_id;
  GET DIAGNOSTICS affected_artifacts = ROW_COUNT;
  RETURN affected_artifacts = 1;
END;
$$;

CREATE FUNCTION kovcheg.revoke_oidc_provider_artifacts_by_grant_id(p_grant_id text)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  affected_artifacts integer;
BEGIN
  DELETE FROM kovcheg.oidc_provider_artifacts WHERE grant_id = p_grant_id;
  GET DIAGNOSTICS affected_artifacts = ROW_COUNT;
  RETURN affected_artifacts;
END;
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA kovcheg FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA kovcheg FROM PUBLIC;

REVOKE ALL ON FUNCTION kovcheg.find_auth_account_by_id(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.create_auth_account(uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.bootstrap_auth_administrator(text, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.issue_auth_challenge_for_active_account(
  text, uuid, text, timestamptz, timestamptz, integer, interval
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.consume_auth_challenge_and_create_session(
  uuid, text, timestamptz, uuid, text, timestamptz, bigint, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.authenticate_auth_session(text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.invalidate_auth_challenge(uuid, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.revoke_auth_session_by_id(uuid, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.revoke_auth_session_by_verifier(text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.set_auth_account_status_and_revoke(
  uuid, kovcheg.account_status, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.find_registered_oidc_client(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.oidc_redirect_uri_is_registered(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.upsert_oidc_provider_artifact(
  text, text, jsonb, timestamptz, text, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.find_oidc_provider_artifact(text, text, timestamptz)
FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.find_oidc_provider_artifact_by_user_code(text, timestamptz)
FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.find_oidc_provider_artifact_by_uid(text, timestamptz)
FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.consume_oidc_provider_artifact(text, text, timestamptz)
FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.destroy_oidc_provider_artifact(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.revoke_oidc_provider_artifacts_by_grant_id(text)
FROM PUBLIC;

GRANT USAGE ON SCHEMA kovcheg TO kovcheg_auth_runtime;
GRANT USAGE ON TYPE
  kovcheg.account_status,
  kovcheg.auth_account_role,
  kovcheg.oidc_token_endpoint_auth_method
TO kovcheg_auth_runtime;

GRANT EXECUTE ON FUNCTION
  kovcheg.find_auth_account_by_id(uuid),
  kovcheg.create_auth_account(uuid, text, text),
  kovcheg.bootstrap_auth_administrator(text, uuid, text, text),
  kovcheg.issue_auth_challenge_for_active_account(
    text, uuid, text, timestamptz, timestamptz, integer, interval
  ),
  kovcheg.consume_auth_challenge_and_create_session(
    uuid, text, timestamptz, uuid, text, timestamptz, bigint, timestamptz
  ),
  kovcheg.authenticate_auth_session(text, timestamptz),
  kovcheg.invalidate_auth_challenge(uuid, timestamptz),
  kovcheg.revoke_auth_session_by_id(uuid, timestamptz),
  kovcheg.revoke_auth_session_by_verifier(text, timestamptz),
  kovcheg.set_auth_account_status_and_revoke(uuid, kovcheg.account_status, timestamptz),
  kovcheg.find_registered_oidc_client(text),
  kovcheg.oidc_redirect_uri_is_registered(text, text),
  kovcheg.upsert_oidc_provider_artifact(
    text, text, jsonb, timestamptz, text, text, text
  ),
  kovcheg.find_oidc_provider_artifact(text, text, timestamptz),
  kovcheg.find_oidc_provider_artifact_by_user_code(text, timestamptz),
  kovcheg.find_oidc_provider_artifact_by_uid(text, timestamptz),
  kovcheg.consume_oidc_provider_artifact(text, text, timestamptz),
  kovcheg.destroy_oidc_provider_artifact(text, text),
  kovcheg.revoke_oidc_provider_artifacts_by_grant_id(text)
TO kovcheg_auth_runtime;

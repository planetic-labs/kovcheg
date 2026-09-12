CREATE FUNCTION kovcheg.require_active_auth_administrator_for_target(
  p_actor_session_verifier text,
  p_target_account_id uuid,
  p_now timestamptz
)
RETURNS uuid
LANGUAGE plpgsql
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  owner_account_id uuid;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  SELECT owner_boundary.account_id
  INTO owner_account_id
  FROM kovcheg.server_owner AS owner_boundary
  WHERE owner_boundary.singleton;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'server owner boundary is unavailable' USING ERRCODE = '55000';
  END IF;

  IF p_target_account_id = owner_account_id
    AND actor_account_id <> owner_account_id
  THEN
    RAISE EXCEPTION 'server owner authorization required' USING ERRCODE = '42501';
  END IF;

  RETURN actor_account_id;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.require_active_auth_administrator_for_target(
  text, uuid, timestamptz
) FROM PUBLIC;

CREATE OR REPLACE FUNCTION kovcheg.admin_update_auth_account(
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
  auth_role kovcheg.auth_account_role,
  account_status kovcheg.account_status
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  normalized_email text := pg_catalog.lower(pg_catalog.btrim(p_email));
  normalized_display_name text := pg_catalog.btrim(p_display_name);
  target_created_at timestamptz;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator_for_target(
    p_actor_session_verifier,
    p_account_id,
    p_now
  );

  SELECT profile.created_at
  INTO target_created_at
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.account_id = p_account_id
  FOR UPDATE OF profile, account;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'auth account target not found' USING ERRCODE = 'P0002';
  END IF;

  IF p_now < target_created_at THEN
    RAISE EXCEPTION 'operation time precedes auth account creation'
      USING ERRCODE = '23514';
  END IF;

  UPDATE kovcheg.account_auth_profiles AS profile
  SET email = normalized_email,
      display_name = normalized_display_name,
      updated_at = p_now
  WHERE profile.account_id = p_account_id;

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    'auth.account.updated',
    'auth_account',
    p_account_id,
    'success',
    '{}'::jsonb
  );

  RETURN QUERY
  SELECT * FROM kovcheg.find_auth_account_by_id(p_account_id);
END;
$$;

CREATE OR REPLACE FUNCTION kovcheg.admin_set_auth_account_status(
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
  auth_role kovcheg.auth_account_role,
  account_status kovcheg.account_status
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  invalidated_challenge_count integer := 0;
  revoked_session_count integer := 0;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator_for_target(
    p_actor_session_verifier,
    p_account_id,
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

  UPDATE kovcheg.accounts AS account
  SET status = p_status,
      activated_at = CASE
        WHEN p_status = 'active' THEN COALESCE(account.activated_at, p_now)
        ELSE account.activated_at
      END,
      deactivated_at = CASE WHEN p_status = 'deactivated' THEN p_now ELSE NULL END
  WHERE account.id = p_account_id;

  IF p_status = 'deactivated' THEN
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
    GET DIAGNOSTICS revoked_session_count = ROW_COUNT;
  END IF;

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    'auth.account.status-set',
    'auth_account',
    p_account_id,
    'success',
    pg_catalog.jsonb_build_object(
      'accountStatus', p_status,
      'invalidatedChallengeCount', invalidated_challenge_count,
      'revokedSessionCount', revoked_session_count
    )
  );

  RETURN QUERY
  SELECT * FROM kovcheg.find_auth_account_by_id(p_account_id);
END;
$$;

CREATE OR REPLACE FUNCTION kovcheg.admin_revoke_auth_session(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_session_id uuid,
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
  affected_sessions integer;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator_for_target(
    p_actor_session_verifier,
    p_account_id,
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

  UPDATE kovcheg.auth_sessions AS session
  SET revoked_at = GREATEST(p_now, session.issued_at)
  WHERE session.id = p_session_id
    AND session.account_id = p_account_id
    AND session.revoked_at IS NULL;
  GET DIAGNOSTICS affected_sessions = ROW_COUNT;

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    'auth.session.revoked',
    'auth_account',
    p_account_id,
    'success',
    pg_catalog.jsonb_build_object('revokedSessionCount', affected_sessions)
  );

  RETURN affected_sessions = 1;
END;
$$;

CREATE OR REPLACE FUNCTION kovcheg.admin_revoke_all_auth_sessions(
  p_actor_session_verifier text,
  p_account_id uuid,
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
  affected_sessions integer;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator_for_target(
    p_actor_session_verifier,
    p_account_id,
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

  UPDATE kovcheg.auth_sessions AS session
  SET revoked_at = GREATEST(p_now, session.issued_at)
  WHERE session.account_id = p_account_id
    AND session.revoked_at IS NULL;
  GET DIAGNOSTICS affected_sessions = ROW_COUNT;

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    'auth.session.all-revoked',
    'auth_account',
    p_account_id,
    'success',
    pg_catalog.jsonb_build_object('revokedSessionCount', affected_sessions)
  );

  RETURN affected_sessions;
END;
$$;

CREATE OR REPLACE FUNCTION kovcheg.mutate_functional_grant(
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
  actor_is_owner boolean;
  target_is_owner boolean;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator_for_target(
    p_actor_session_verifier,
    p_account_id,
    p_now
  );
  IF p_grant NOT IN (
    'warrior',
    'platform_administrator',
    'chronicler',
    'editor',
    'technical_administrator'
  ) OR p_reason !~ '^[a-z][a-z0-9.-]{2,63}$' THEN
    RAISE EXCEPTION 'invalid functional grant mutation' USING ERRCODE = '23514';
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM kovcheg.server_owner AS owner_boundary
    WHERE owner_boundary.singleton AND owner_boundary.account_id = actor_account_id
  ) INTO actor_is_owner;
  SELECT EXISTS (
    SELECT 1 FROM kovcheg.server_owner AS owner_boundary
    WHERE owner_boundary.singleton AND owner_boundary.account_id = p_account_id
  ) INTO target_is_owner;

  IF p_grant = 'platform_administrator' AND NOT actor_is_owner THEN
    RAISE EXCEPTION 'server owner authorization required' USING ERRCODE = '42501';
  END IF;
  IF p_grant = 'platform_administrator' AND target_is_owner AND NOT p_granted THEN
    RAISE EXCEPTION 'server owner administrator grant cannot be revoked'
      USING ERRCODE = '23514';
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
  migration_version text;
  result jsonb;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator_for_target(
    p_actor_session_verifier,
    p_account_id,
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

  UPDATE kovcheg.auth_sessions AS application_session
  SET revoked_at = GREATEST(p_now, application_session.issued_at)
  WHERE application_session.account_id = p_account_id
    AND application_session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_application_session_count = ROW_COUNT;

  result := pg_catalog.jsonb_build_object(
    'revokedFamilyCount', revoked_family_count,
    'revokedGateSessionCount', revoked_gate_session_count,
    'revokedPasskeyCount', revoked_passkey_count,
    'invalidatedChallengeCount', invalidated_challenge_count,
    'revokedApplicationSessionCount', revoked_application_session_count
  );

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    'auth.access.security-reset',
    'auth_account',
    p_account_id,
    'success',
    pg_catalog.jsonb_build_object(
      'retiredGateFamilyCount', revoked_family_count,
      'retiredGateSessionCount', revoked_gate_session_count,
      'revokedPasskeyCount', revoked_passkey_count,
      'invalidatedChallengeCount', invalidated_challenge_count,
      'revokedApplicationSessionCount', revoked_application_session_count
    )
  );

  RETURN result;
END;
$$;

CREATE FUNCTION kovcheg.admin_list_role_capable_accounts(
  p_actor_session_verifier text,
  p_after_account_id uuid,
  p_page_size integer,
  p_now timestamptz
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  account_status kovcheg.account_status,
  has_more boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  PERFORM kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  IF p_page_size IS NULL OR p_page_size NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'invalid account page size' USING ERRCODE = '23514';
  END IF;

  RETURN QUERY
  WITH requested AS MATERIALIZED (
    SELECT
      account.id AS requested_account_id,
      profile.email AS requested_email,
      profile.display_name AS requested_display_name,
      account.status AS requested_account_status
    FROM kovcheg.accounts AS account
    JOIN kovcheg.account_auth_profiles AS profile
      ON profile.account_id = account.id
    WHERE account.kind = 'person'
      AND (p_after_account_id IS NULL OR account.id > p_after_account_id)
    ORDER BY account.id
    LIMIT (p_page_size + 1)
  ), numbered AS (
    SELECT
      requested.*,
      pg_catalog.row_number() OVER (
        ORDER BY requested.requested_account_id
      ) AS page_row_number,
      pg_catalog.count(*) OVER () AS requested_count
    FROM requested
  )
  SELECT
    numbered.requested_account_id,
    numbered.requested_email,
    numbered.requested_display_name,
    numbered.requested_account_status,
    numbered.requested_count > p_page_size
  FROM numbered
  WHERE numbered.page_row_number <= p_page_size
  ORDER BY numbered.requested_account_id;
END;
$$;

CREATE FUNCTION kovcheg.admin_read_role_capable_account(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_now timestamptz
)
RETURNS TABLE (
  account_id uuid,
  email varchar,
  display_name varchar,
  account_access text,
  account_status kovcheg.account_status,
  domain_status kovcheg.domain_status,
  functional_grants text[],
  authorization_version bigint,
  is_server_owner boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  PERFORM kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  RETURN QUERY
  SELECT
    readable.account_id,
    readable.email,
    readable.display_name,
    readable.account_access,
    readable.account_status,
    readable.domain_status,
    readable.functional_grants,
    domain.authorization_version,
    owner_boundary.account_id IS NOT NULL
  FROM kovcheg.read_role_capable_account(p_account_id) AS readable
  JOIN kovcheg.account_domain_statuses AS domain
    ON domain.account_id = readable.account_id
  LEFT JOIN kovcheg.server_owner AS owner_boundary
    ON owner_boundary.singleton
   AND owner_boundary.account_id = readable.account_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'account target not found' USING ERRCODE = 'P0002';
  END IF;
END;
$$;

CREATE FUNCTION kovcheg.read_own_auth_passkey_settings(
  p_application_session_verifier text,
  p_now timestamptz
)
RETURNS TABLE (
  ever_added boolean,
  active_passkey_count bigint,
  active_passkeys jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  authorized_account_id uuid;
BEGIN
  SELECT session.account_id
  INTO authorized_account_id
  FROM kovcheg.validate_auth_session(
    p_application_session_verifier,
    p_now
  ) AS session;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey settings authorization failed' USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT
    pg_catalog.count(*) > 0,
    pg_catalog.count(*) FILTER (WHERE passkey.revoked_at IS NULL),
    COALESCE(
      pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
          'id', passkey.id,
          'createdAt', passkey.created_at,
          'lastUsedAt', passkey.last_used_at,
          'status', 'active'
        )
        ORDER BY passkey.created_at, passkey.id
      ) FILTER (WHERE passkey.revoked_at IS NULL),
      '[]'::jsonb
    )
  FROM kovcheg.auth_passkey_credentials AS passkey
  WHERE passkey.account_id = authorized_account_id;
END;
$$;

CREATE FUNCTION kovcheg.revoke_own_auth_passkey(
  p_application_session_verifier text,
  p_passkey_id uuid,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  authorized_account_id uuid;
  existing_revoked_at timestamptz;
  remaining_active_count bigint;
BEGIN
  IF p_passkey_id IS NULL
    OR p_now IS NULL
    OR p_correlation_id IS NULL
    OR p_correlation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  THEN
    RAISE EXCEPTION 'invalid passkey revocation input' USING ERRCODE = '23514';
  END IF;

  SELECT session.account_id
  INTO authorized_account_id
  FROM kovcheg.auth_sessions AS session
  JOIN kovcheg.account_auth_profiles AS profile
    ON profile.account_id = session.account_id
  JOIN kovcheg.accounts AS account
    ON account.id = profile.account_id
  WHERE session.token_verifier = p_application_session_verifier
    AND session.revoked_at IS NULL
    AND p_now >= session.issued_at
    AND p_now < session.idle_expires_at
    AND p_now < session.absolute_expires_at
    AND account.kind = 'person'
    AND account.status = 'active'
  FOR UPDATE OF session, profile, account;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey revocation authorization failed' USING ERRCODE = '42501';
  END IF;

  SELECT passkey.revoked_at
  INTO existing_revoked_at
  FROM kovcheg.auth_passkey_credentials AS passkey
  WHERE passkey.id = p_passkey_id
    AND passkey.account_id = authorized_account_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey target not found' USING ERRCODE = 'P0002';
  END IF;

  IF existing_revoked_at IS NOT NULL THEN
    RETURN false;
  END IF;

  UPDATE kovcheg.auth_passkey_credentials AS passkey
  SET revoked_at = GREATEST(p_now, passkey.created_at)
  WHERE passkey.id = p_passkey_id;

  SELECT pg_catalog.count(*)
  INTO remaining_active_count
  FROM kovcheg.auth_passkey_credentials AS passkey
  WHERE passkey.account_id = authorized_account_id
    AND passkey.revoked_at IS NULL;

  PERFORM kovcheg.auth_passkey_audit(
    p_correlation_id,
    authorized_account_id,
    'auth.passkey.revoked',
    p_passkey_id,
    pg_catalog.jsonb_build_object(
      'remainingActiveCount', remaining_active_count
    )
  );

  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION kovcheg.admin_set_domain_status(
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
  actor_account_id := kovcheg.require_active_auth_administrator_for_target(
    p_actor_session_verifier,
    p_account_id,
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
      UPDATE kovcheg.chat_memberships AS membership
      SET status = 'revoked', revoked_at = p_now
      WHERE membership.chat_id = chat_policy.chat_id
        AND membership.account_id = p_account_id
        AND membership.status = 'active';
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

REVOKE ALL ON FUNCTION kovcheg.admin_list_role_capable_accounts(
  text, uuid, integer, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_read_role_capable_account(
  text, uuid, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.read_own_auth_passkey_settings(
  text, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.revoke_own_auth_passkey(
  text, uuid, timestamptz, varchar
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
  kovcheg.admin_list_role_capable_accounts(text, uuid, integer, timestamptz),
  kovcheg.admin_read_role_capable_account(text, uuid, timestamptz),
  kovcheg.read_own_auth_passkey_settings(text, timestamptz),
  kovcheg.revoke_own_auth_passkey(text, uuid, timestamptz, varchar)
TO kovcheg_auth_runtime;

COMMENT ON FUNCTION kovcheg.admin_list_role_capable_accounts(
  text, uuid, integer, timestamptz
) IS 'Bounded stable account summaries for an active authorized administrator.';
COMMENT ON FUNCTION kovcheg.admin_read_role_capable_account(
  text, uuid, timestamptz
) IS 'Current account authorization state for an active authorized administrator.';
COMMENT ON FUNCTION kovcheg.read_own_auth_passkey_settings(
  text, timestamptz
) IS 'Safe active-passkey settings projection for the current application session owner.';
COMMENT ON FUNCTION kovcheg.revoke_own_auth_passkey(
  text, uuid, timestamptz, varchar
) IS 'Idempotently revokes one passkey owned by the current application session account.';

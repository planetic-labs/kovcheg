CREATE FUNCTION kovcheg.require_active_auth_administrator(
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
  JOIN kovcheg.account_auth_profiles AS profile
    ON profile.account_id = session.account_id
  JOIN kovcheg.accounts AS account
    ON account.id = profile.account_id
  WHERE session.token_verifier = p_actor_session_verifier
    AND session.revoked_at IS NULL
    AND p_now >= session.issued_at
    AND p_now < session.idle_expires_at
    AND p_now < session.absolute_expires_at
    AND profile.auth_role = 'administrator'
    AND account.status = 'active'
  FOR UPDATE OF session, profile, account;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'administrative authorization failed' USING ERRCODE = '42501';
  END IF;

  RETURN actor_account_id;
END;
$$;

CREATE FUNCTION kovcheg.admin_create_auth_account(
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
  blueprint record;
  direct_chat_id uuid;
  required_count integer;
  starter_chat_count integer;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  SELECT count(*)::integer
  INTO required_count
  FROM kovcheg.starter_chat_blueprints
  WHERE is_required;

  IF required_count = 0 THEN
    RAISE EXCEPTION 'required starter chat set is empty' USING ERRCODE = '23514';
  END IF;

  INSERT INTO kovcheg.accounts (id, status, created_at, activated_at)
  VALUES (p_account_id, 'active', p_now, p_now);

  FOR blueprint IN
    SELECT *
    FROM kovcheg.starter_chat_blueprints
    WHERE is_required
    ORDER BY slug
  LOOP
    IF blueprint.shared_chat_id IS NOT NULL THEN
      INSERT INTO kovcheg.chat_memberships (chat_id, account_id, joined_at)
      VALUES (blueprint.shared_chat_id, p_account_id, p_now);
    ELSE
      INSERT INTO kovcheg.chats (
        kind,
        starter_blueprint_id,
        provisioned_for_account_id,
        created_by_account_id,
        created_at
      ) VALUES (
        blueprint.chat_kind,
        blueprint.id,
        p_account_id,
        p_account_id,
        p_now
      ) RETURNING id INTO direct_chat_id;

      INSERT INTO kovcheg.chat_memberships (
        chat_id,
        account_id,
        role,
        joined_at
      ) VALUES
        (direct_chat_id, p_account_id, 'member', p_now),
        (direct_chat_id, blueprint.counterpart_account_id, 'synthetic_system', p_now);
    END IF;
  END LOOP;

  SELECT count(*)::integer
  INTO starter_chat_count
  FROM kovcheg.chat_memberships AS membership
  WHERE membership.account_id = p_account_id
    AND membership.status = 'active';

  IF starter_chat_count = 0 THEN
    RAISE EXCEPTION 'account provisioning produced an empty starter set'
      USING ERRCODE = '23514';
  END IF;

  INSERT INTO kovcheg.account_auth_profiles (
    account_id,
    email,
    display_name,
    auth_role,
    created_at,
    updated_at
  ) VALUES (
    p_account_id,
    normalized_email,
    normalized_display_name,
    'student',
    p_now,
    p_now
  );

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    'auth.account.created',
    'auth_account',
    p_account_id,
    'success',
    pg_catalog.jsonb_build_object(
      'authRole', 'student',
      'accountStatus', 'active',
      'starterChatCount', starter_chat_count
    )
  );

  RETURN QUERY
  SELECT * FROM kovcheg.find_auth_account_by_id(p_account_id);
END;
$$;

CREATE FUNCTION kovcheg.admin_update_auth_account(
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
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
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

CREATE FUNCTION kovcheg.admin_set_auth_account_status(
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

CREATE FUNCTION kovcheg.admin_revoke_auth_session(
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

CREATE FUNCTION kovcheg.admin_revoke_all_auth_sessions(
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

REVOKE ALL ON FUNCTION kovcheg.require_active_auth_administrator(text, timestamptz)
FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_create_auth_account(
  text, uuid, text, text, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_update_auth_account(
  text, uuid, text, text, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_set_auth_account_status(
  text, uuid, kovcheg.account_status, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_revoke_auth_session(
  text, uuid, uuid, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.admin_revoke_all_auth_sessions(
  text, uuid, timestamptz, varchar
) FROM PUBLIC;

REVOKE EXECUTE ON FUNCTION kovcheg.create_auth_account(uuid, text, text)
FROM kovcheg_auth_runtime;
REVOKE EXECUTE ON FUNCTION kovcheg.set_auth_account_status_and_revoke(
  uuid, kovcheg.account_status, timestamptz
) FROM kovcheg_auth_runtime;
REVOKE EXECUTE ON FUNCTION kovcheg.revoke_auth_session_by_id(uuid, timestamptz)
FROM kovcheg_auth_runtime;

GRANT EXECUTE ON FUNCTION
  kovcheg.admin_create_auth_account(text, uuid, text, text, timestamptz, varchar),
  kovcheg.admin_update_auth_account(text, uuid, text, text, timestamptz, varchar),
  kovcheg.admin_set_auth_account_status(
    text, uuid, kovcheg.account_status, timestamptz, varchar
  ),
  kovcheg.admin_revoke_auth_session(text, uuid, uuid, timestamptz, varchar),
  kovcheg.admin_revoke_all_auth_sessions(text, uuid, timestamptz, varchar)
TO kovcheg_auth_runtime;

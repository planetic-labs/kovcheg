ALTER TYPE kovcheg.platform_role ADD VALUE 'editor';
ALTER TYPE kovcheg.platform_role ADD VALUE 'technical_administrator';

CREATE TABLE kovcheg.server_owner (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  account_id uuid NOT NULL UNIQUE REFERENCES kovcheg.accounts (id) ON DELETE RESTRICT,
  established_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO kovcheg.server_owner (account_id, established_at)
SELECT bootstrap.account_id, bootstrap.created_at
FROM kovcheg.auth_administrator_bootstraps AS bootstrap
ORDER BY bootstrap.created_at, bootstrap.bootstrap_id
LIMIT 1;

CREATE OR REPLACE FUNCTION kovcheg.bootstrap_role_capable_administrator(
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
  existing_owner_account_id uuid;
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('kovcheg.server-owner-bootstrap', 0)
  );

  SELECT owner_boundary.account_id
  INTO existing_owner_account_id
  FROM kovcheg.server_owner AS owner_boundary
  WHERE owner_boundary.singleton
  FOR UPDATE;

  IF FOUND AND existing_owner_account_id <> p_account_id THEN
    RAISE EXCEPTION 'server owner is already established'
      USING ERRCODE = '23505', CONSTRAINT = 'server_owner_pkey';
  END IF;

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
  INSERT INTO kovcheg.server_owner (account_id)
  VALUES (bootstrap_result.account_id)
  ON CONFLICT ON CONSTRAINT server_owner_pkey DO NOTHING;

  RETURN QUERY
  SELECT account.*, bootstrap_result.created
  FROM kovcheg.read_role_capable_account(bootstrap_result.account_id) AS account;
END;
$$;

CREATE OR REPLACE FUNCTION kovcheg.read_current_principal_authorization(
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
  is_owner boolean;
  is_technical_administrator boolean;
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

  IF NOT FOUND THEN RETURN NULL; END IF;

  SELECT * INTO account_readback
  FROM kovcheg.read_role_capable_account(principal_account_id);
  IF NOT FOUND OR account_readback.account_status <> 'active' THEN RETURN NULL; END IF;

  is_administrator := 'platform_administrator' = ANY(account_readback.functional_grants);
  is_technical_administrator :=
    'technical_administrator' = ANY(account_readback.functional_grants);
  SELECT EXISTS (
    SELECT 1 FROM kovcheg.server_owner AS owner_boundary
    WHERE owner_boundary.singleton AND owner_boundary.account_id = principal_account_id
  ) INTO is_owner;

  RETURN pg_catalog.jsonb_build_object(
    'contractVersion', 2,
    'accountAccess', account_readback.account_access,
    'accountStatus', account_readback.account_status,
    'sessionStatus', 'active',
    'userId', principal_account_id,
    'sessionId', principal_session_id,
    'domainStatus', account_readback.domain_status,
    'functionalGrants', pg_catalog.to_jsonb(account_readback.functional_grants),
    'isServerOwner', is_owner,
    'administrativeCapabilities', pg_catalog.jsonb_build_object(
      'canManageAccounts', is_administrator,
      'canManageDomainStatus', is_administrator,
      'canManageFunctionalGrants', is_administrator,
      'canManagePlatformAdministrators', is_owner
    ),
    'diagnosticCapabilities', pg_catalog.jsonb_build_object(
      'canReadHealthAndReadiness', is_technical_administrator,
      'canReadBuildAndMigrationVersions', is_technical_administrator,
      'canReadQueueAndTechnicalState', is_technical_administrator,
      'canReadSanitizedDiagnostics', is_technical_administrator
    ),
    'materialCapabilities', '[]'::jsonb,
    'sensitiveCapabilities', pg_catalog.jsonb_build_object(
      'canPerformSensitiveActions', false
    )
  );
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
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
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

CREATE TABLE kovcheg.chat_administration_versions (
  chat_id uuid PRIMARY KEY REFERENCES kovcheg.chats (id) ON DELETE CASCADE,
  authorization_version bigint NOT NULL DEFAULT 1 CHECK (authorization_version > 0),
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO kovcheg.chat_administration_versions (chat_id)
SELECT chat.id FROM kovcheg.chats AS chat WHERE chat.kind = 'group';

UPDATE kovcheg.chat_memberships AS membership
SET is_administrator = true
FROM kovcheg.chats AS chat, kovcheg.accounts AS creator
WHERE chat.id = membership.chat_id
  AND creator.id = chat.created_by_account_id
  AND chat.kind = 'group'
  AND creator.kind = 'person'
  AND creator.status = 'active'
  AND membership.account_id = chat.created_by_account_id
  AND membership.status = 'active';

CREATE OR REPLACE FUNCTION kovcheg.can_account_manage_chat_members(
  p_account_id uuid,
  p_chat_id uuid
)
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
      AND account.kind = 'person'
      AND account.status = 'active'
      AND membership.chat_id = p_chat_id
      AND membership.status = 'active'
      AND (
        membership.is_administrator
        OR EXISTS (
          SELECT 1 FROM kovcheg.account_platform_roles AS role
          WHERE role.account_id = account.id AND role.role = 'warrior'
        )
      )
  );
$$;

CREATE FUNCTION kovcheg.can_account_manage_chat_administrators(
  p_account_id uuid,
  p_chat_id uuid
)
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
    JOIN kovcheg.chats AS chat ON chat.id = membership.chat_id
    WHERE account.id = p_account_id
      AND account.kind = 'person'
      AND account.status = 'active'
      AND membership.chat_id = p_chat_id
      AND membership.status = 'active'
      AND chat.kind = 'group'
      AND (
        chat.created_by_account_id = account.id
        OR EXISTS (
          SELECT 1 FROM kovcheg.account_platform_roles AS role
          WHERE role.account_id = account.id AND role.role = 'warrior'
        )
      )
  );
$$;

REVOKE ALL ON FUNCTION kovcheg.can_account_manage_chat_administrators(uuid, uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION kovcheg.can_account_assign_chat_labels(
  p_account_id uuid,
  p_chat_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT kovcheg.can_account_manage_chat_members(p_account_id, p_chat_id);
$$;

CREATE OR REPLACE FUNCTION kovcheg.list_account_chat_capabilities(p_account_id uuid)
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

CREATE FUNCTION kovcheg.require_active_personal_application_session(
  p_session_id uuid,
  p_actor_account_id uuid,
  p_now timestamptz
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  authorized_actor_account_id uuid;
BEGIN
  SELECT session.account_id
  INTO authorized_actor_account_id
  FROM kovcheg.auth_sessions AS session
  JOIN kovcheg.account_auth_profiles AS profile ON profile.account_id = session.account_id
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE session.id = p_session_id
    AND session.account_id = p_actor_account_id
    AND session.revoked_at IS NULL
    AND p_now >= session.issued_at
    AND p_now < session.idle_expires_at
    AND p_now < session.absolute_expires_at
    AND account.kind = 'person'
    AND account.status = 'active'
  FOR SHARE OF session, profile, account;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'chat administration authorization failed' USING ERRCODE = '42501';
  END IF;
  RETURN authorized_actor_account_id;
END;
$$;

CREATE FUNCTION kovcheg.create_group_chat_for_session(
  p_chat_id uuid,
  p_session_id uuid,
  p_actor_account_id uuid,
  p_reason varchar,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  chat_id uuid,
  target_account_id uuid,
  is_administrator boolean,
  authorization_version bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_personal_application_session(
    p_session_id, p_actor_account_id, p_now
  );
  IF p_reason !~ '^[a-z][a-z0-9.-]{2,63}$' THEN
    RAISE EXCEPTION 'invalid chat administration reason' USING ERRCODE = '23514';
  END IF;

  INSERT INTO kovcheg.chats (id, kind, created_by_account_id, created_at)
  VALUES (p_chat_id, 'group', actor_account_id, p_now);
  INSERT INTO kovcheg.chat_memberships (
    chat_id, account_id, is_administrator, joined_at
  ) VALUES (p_chat_id, actor_account_id, true, p_now);
  INSERT INTO kovcheg.chat_administration_versions (chat_id, changed_at)
  VALUES (p_chat_id, p_now);

  migration_version := kovcheg.current_migration_version();
  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    'chat.group.created',
    'chat',
    p_chat_id,
    'success',
    pg_catalog.jsonb_build_object(
      'chatId', p_chat_id,
      'reasonCode', p_reason,
      'authorizationVersion', 1
    )
  );

  RETURN QUERY SELECT p_chat_id, actor_account_id, true, 1::bigint;
END;
$$;

CREATE FUNCTION kovcheg.set_chat_administrator_for_session(
  p_chat_id uuid,
  p_session_id uuid,
  p_actor_account_id uuid,
  p_target_account_id uuid,
  p_granted boolean,
  p_reason varchar,
  p_authorization_version bigint,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS TABLE (
  chat_id uuid,
  target_account_id uuid,
  is_administrator boolean,
  authorization_version bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  previous_granted boolean;
  previous_version bigint;
  chat_creator_account_id uuid;
  migration_version text;
BEGIN
  actor_account_id := kovcheg.require_active_personal_application_session(
    p_session_id, p_actor_account_id, p_now
  );
  IF p_reason !~ '^[a-z][a-z0-9.-]{2,63}$' THEN
    RAISE EXCEPTION 'invalid chat administration reason' USING ERRCODE = '23514';
  END IF;

  SELECT chat.created_by_account_id, version.authorization_version
  INTO chat_creator_account_id, previous_version
  FROM kovcheg.chats AS chat
  JOIN kovcheg.chat_administration_versions AS version ON version.chat_id = chat.id
  WHERE chat.id = p_chat_id AND chat.kind = 'group'
  FOR UPDATE OF chat, version;
  IF NOT FOUND THEN RAISE EXCEPTION 'group chat not found' USING ERRCODE = 'P0002'; END IF;
  IF p_authorization_version <> previous_version + 1 THEN
    RAISE EXCEPTION 'authorization version conflict' USING ERRCODE = '23505';
  END IF;
  IF NOT kovcheg.can_account_manage_chat_administrators(actor_account_id, p_chat_id) THEN
    RAISE EXCEPTION 'chat administration authorization failed' USING ERRCODE = '42501';
  END IF;
  IF p_target_account_id = chat_creator_account_id AND NOT p_granted THEN
    RAISE EXCEPTION 'group creator administrator cannot be revoked' USING ERRCODE = '23514';
  END IF;

  SELECT membership.is_administrator
  INTO previous_granted
  FROM kovcheg.chat_memberships AS membership
  JOIN kovcheg.accounts AS target ON target.id = membership.account_id
  WHERE membership.chat_id = p_chat_id
    AND membership.account_id = p_target_account_id
    AND membership.status = 'active'
    AND target.kind = 'person'
    AND target.status = 'active'
  FOR UPDATE OF membership, target;
  IF NOT FOUND THEN RAISE EXCEPTION 'chat member target not found' USING ERRCODE = 'P0002'; END IF;
  IF previous_granted = p_granted THEN
    RAISE EXCEPTION 'chat administrator state conflict' USING ERRCODE = '23505';
  END IF;

  UPDATE kovcheg.chat_memberships AS membership
  SET is_administrator = p_granted
  WHERE membership.chat_id = p_chat_id AND membership.account_id = p_target_account_id;
  UPDATE kovcheg.chat_administration_versions AS version
  SET authorization_version = p_authorization_version, changed_at = p_now
  WHERE version.chat_id = p_chat_id;

  migration_version := kovcheg.current_migration_version();
  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    CASE WHEN p_granted THEN 'chat.administrator.granted'
         ELSE 'chat.administrator.revoked' END,
    'chat_account',
    p_target_account_id,
    'success',
    pg_catalog.jsonb_build_object(
      'chatId', p_chat_id,
      'previousGranted', previous_granted,
      'newGranted', p_granted,
      'reasonCode', p_reason,
      'authorizationVersion', p_authorization_version
    )
  );

  RETURN QUERY
  SELECT p_chat_id, p_target_account_id, p_granted, p_authorization_version;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.require_active_personal_application_session(
  uuid, uuid, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.create_group_chat_for_session(
  uuid, uuid, uuid, varchar, timestamptz, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.set_chat_administrator_for_session(
  uuid, uuid, uuid, uuid, boolean, varchar, bigint, timestamptz, varchar
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION kovcheg.can_account_manage_chat_administrators(uuid, uuid)
TO kovcheg_runtime;
GRANT EXECUTE ON FUNCTION kovcheg.create_group_chat_for_session(
  uuid, uuid, uuid, varchar, timestamptz, varchar
) TO kovcheg_runtime;
GRANT EXECUTE ON FUNCTION kovcheg.set_chat_administrator_for_session(
  uuid, uuid, uuid, uuid, boolean, varchar, bigint, timestamptz, varchar
) TO kovcheg_runtime;

COMMENT ON TABLE kovcheg.server_owner IS
  'Unique server trust boundary established by the first administrator bootstrap; not a functional grant.';
COMMENT ON TABLE kovcheg.chat_administration_versions IS
  'Optimistic authorization version for scoped group-chat administrator mutations.';
COMMENT ON FUNCTION kovcheg.read_current_principal_authorization(text, timestamptz, boolean) IS
  'Versioned server-authoritative account, owner, delegated administration, diagnostics, and empty material-capability readback.';
COMMENT ON FUNCTION kovcheg.create_group_chat_for_session(
  uuid, uuid, uuid, varchar, timestamptz, varchar
) IS
  'Creates the minimal user group boundary and atomically makes its authenticated creator the first scoped administrator.';

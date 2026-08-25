CREATE FUNCTION pg_temp.assert_true(assertion boolean, message text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  IF assertion IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'assertion failed: %', message;
  END IF;
END;
$$;

SELECT pg_temp.assert_true(
  (SELECT count(*) = 1 FROM kovcheg.server_owner)
  AND (
    SELECT account_id = '00000000-0000-4000-8000-000000003001'
    FROM kovcheg.server_owner
    WHERE singleton
  ),
  'the first bootstrap trust root must establish one neutral server-owner boundary'
);

SELECT pg_temp.assert_true(
  (
    SELECT principal @> pg_catalog.jsonb_build_object(
      'contractVersion', 2,
      'isServerOwner', true
    )
      AND principal -> 'administrativeCapabilities' ->
        'canManagePlatformAdministrators' = 'true'::jsonb
      AND principal -> 'sensitiveCapabilities' ->
        'canPerformSensitiveActions' = 'false'::jsonb
    FROM (
      SELECT kovcheg.read_current_principal_authorization(
        repeat('m', 43),
        '2030-01-01 00:22:59+00',
        false
      ) AS principal
    ) AS owner_readback
  ),
  'owner-only and separate sensitive capabilities must be explicit in principal v2'
);

CREATE TEMP TABLE delegated_administrator AS
SELECT * FROM kovcheg.admin_create_role_capable_account(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000008001',
  'delegated-administrator@identity.invalid',
  'Delegated Administrator',
  '2030-01-01 00:23:00+00',
  'role-followup-create-delegated-administrator'
);

CREATE TEMP TABLE delegated_administrator_grant AS
SELECT * FROM kovcheg.admin_grant_functional_grant(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000008001',
  'platform_administrator',
  'owner-delegated',
  2,
  '2030-01-01 00:23:01+00',
  'role-followup-owner-grant-platform-administrator'
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
  '00000000-0000-4000-8000-000000008201',
  '00000000-0000-4000-8000-000000008001',
  repeat('T', 43),
  '2030-01-01 00:23:01+00',
  '2030-01-01 00:23:01+00',
  3600000,
  '2030-01-01 01:23:01+00',
  '2030-01-02 00:23:01+00'
);

CREATE TEMP TABLE specialist_account AS
SELECT * FROM kovcheg.admin_create_role_capable_account(
  repeat('T', 43),
  '00000000-0000-4000-8000-000000008002',
  'role-specialist@identity.invalid',
  'Role Specialist',
  '2030-01-01 00:23:02+00',
  'role-followup-create-specialist'
);

CREATE TEMP TABLE owner_guard_target AS
SELECT * FROM kovcheg.admin_create_role_capable_account(
  repeat('T', 43),
  '00000000-0000-4000-8000-000000008003',
  'owner-guard-target@identity.invalid',
  'Owner Guard Target',
  '2030-01-01 00:23:03+00',
  'role-followup-create-owner-guard-target'
);

DO $$
BEGIN
  BEGIN
    PERFORM * FROM kovcheg.admin_grant_functional_grant(
      repeat('T', 43),
      '00000000-0000-4000-8000-000000008003',
      'platform_administrator',
      'delegated-denied',
      2,
      '2030-01-01 00:23:04+00',
      'role-followup-delegated-platform-denied'
    );
    RAISE EXCEPTION 'a delegated administrator granted platform administration';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT functional_grants = ARRAY[]::text[]
    FROM kovcheg.read_role_capable_account(
      '00000000-0000-4000-8000-000000008003'
    )
  ),
  'a delegated administrator must not mutate platform-administrator state'
);

SELECT * FROM kovcheg.admin_grant_functional_grant(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000008003',
  'platform_administrator',
  'owner-delegated',
  2,
  '2030-01-01 00:23:05+00',
  'role-followup-owner-grant-platform-target'
);
SELECT * FROM kovcheg.admin_revoke_functional_grant(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000008003',
  'platform_administrator',
  'owner-revoked',
  3,
  '2030-01-01 00:23:06+00',
  'role-followup-owner-revoke-platform-target'
);

CREATE TEMP TABLE editor_grant AS
SELECT * FROM kovcheg.admin_grant_functional_grant(
  repeat('T', 43),
  '00000000-0000-4000-8000-000000008002',
  'editor',
  'delegated-assignment',
  2,
  '2030-01-01 00:23:07+00',
  'role-followup-grant-editor'
);
CREATE TEMP TABLE chronicler_grant AS
SELECT * FROM kovcheg.admin_grant_functional_grant(
  repeat('T', 43),
  '00000000-0000-4000-8000-000000008002',
  'chronicler',
  'delegated-assignment',
  3,
  '2030-01-01 00:23:08+00',
  'role-followup-grant-chronicler'
);
CREATE TEMP TABLE technical_administrator_grant AS
SELECT * FROM kovcheg.admin_grant_functional_grant(
  repeat('T', 43),
  '00000000-0000-4000-8000-000000008002',
  'technical_administrator',
  'delegated-assignment',
  4,
  '2030-01-01 00:23:09+00',
  'role-followup-grant-technical-administrator'
);

SELECT pg_temp.assert_true(
  (SELECT functional_grants = ARRAY['editor'] FROM editor_grant)
  AND (SELECT functional_grants @> ARRAY['chronicler', 'editor'] FROM chronicler_grant)
  AND (
    SELECT functional_grants @> ARRAY['chronicler', 'editor', 'technical_administrator']
    FROM technical_administrator_grant
  ),
  'editor and chronicler must remain independent explicit grants that can coexist'
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
  '00000000-0000-4000-8000-000000008202',
  '00000000-0000-4000-8000-000000008002',
  repeat('U', 43),
  '2030-01-01 00:23:09+00',
  '2030-01-01 00:23:09+00',
  3600000,
  '2030-01-01 01:23:09+00',
  '2030-01-02 00:23:09+00'
);

SELECT pg_temp.assert_true(
  (
    SELECT principal @> pg_catalog.jsonb_build_object(
      'contractVersion', 2,
      'isServerOwner', false,
      'materialCapabilities', pg_catalog.jsonb_build_array(),
      'sensitiveCapabilities', pg_catalog.jsonb_build_object(
        'canPerformSensitiveActions', false
      )
    )
      AND principal -> 'administrativeCapabilities' = pg_catalog.jsonb_build_object(
        'canManageAccounts', false,
        'canManageDomainStatus', false,
        'canManageFunctionalGrants', false,
        'canManagePlatformAdministrators', false
      )
      AND principal -> 'diagnosticCapabilities' = pg_catalog.jsonb_build_object(
        'canReadHealthAndReadiness', true,
        'canReadBuildAndMigrationVersions', true,
        'canReadQueueAndTechnicalState', true,
        'canReadSanitizedDiagnostics', true
      )
    FROM (
      SELECT kovcheg.read_current_principal_authorization(
        repeat('U', 43),
        '2030-01-01 00:23:10+00',
        false
      ) AS principal
    ) AS readback
  ),
  'technical administration must expose only read-only diagnostics and no material or sensitive rights'
);

DO $$
BEGIN
  BEGIN
    PERFORM * FROM kovcheg.admin_set_domain_status(
      repeat('U', 43),
      '00000000-0000-4000-8000-000000007002',
      'disciple',
      'technical-denied',
      2,
      '2030-01-01 00:23:10+00',
      'role-followup-technical-mutation-denied'
    );
    RAISE EXCEPTION 'technical administrator changed authorization state';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  NOT kovcheg.can_account_read_chat(
    '00000000-0000-4000-8000-000000008002',
    (
      SELECT id FROM kovcheg.chats
      WHERE kind = 'direct'
        AND provisioned_for_account_id = '00000000-0000-4000-8000-000000007002'
      ORDER BY id LIMIT 1
    )
  ),
  'technical administrator grant alone must not expose another account content'
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
  '00000000-0000-4000-8000-000000008203',
  '00000000-0000-4000-8000-000000007002',
  repeat('V', 43),
  '2030-01-01 00:23:10+00',
  '2030-01-01 00:23:10+00',
  3600000,
  '2030-01-01 01:23:10+00',
  '2030-01-02 00:23:10+00'
);

INSERT INTO kovcheg.chats (
  id, kind, created_by_account_id, created_at
) VALUES (
  '00000000-0000-4000-8000-000000008100',
  'group',
  '00000000-0000-4000-8000-000000001001',
  '2030-01-01 00:23:10+00'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM kovcheg.chat_memberships
    WHERE chat_id = '00000000-0000-4000-8000-000000008100'
  )
  AND NOT EXISTS (
    SELECT 1 FROM kovcheg.chat_administration_versions
    WHERE chat_id = '00000000-0000-4000-8000-000000008100'
  ),
  'direct chat inserts outside the authenticated operation must not create administrator state'
);

CREATE TEMP TABLE created_group AS
SELECT * FROM kovcheg.create_group_chat_for_session(
  '00000000-0000-4000-8000-000000008101',
  '00000000-0000-4000-8000-000000008203',
  '00000000-0000-4000-8000-000000007002',
  'creator-created',
  '2030-01-01 00:23:11+00',
  'role-followup-create-group'
);

SELECT pg_temp.assert_true(
  (
    SELECT target_account_id = '00000000-0000-4000-8000-000000007002'
      AND is_administrator
      AND authorization_version = 1
    FROM created_group
  )
  AND (
    SELECT is_administrator AND status = 'active'
    FROM kovcheg.chat_memberships
    WHERE chat_id = '00000000-0000-4000-8000-000000008101'
      AND account_id = '00000000-0000-4000-8000-000000007002'
  ),
  'authenticated group creation must atomically make the active personal creator administrator'
);

INSERT INTO kovcheg.chat_memberships (chat_id, account_id, joined_at) VALUES
  (
    '00000000-0000-4000-8000-000000008101',
    '00000000-0000-4000-8000-000000008003',
    '2030-01-01 00:23:12+00'
  ),
  (
    '00000000-0000-4000-8000-000000008101',
    '00000000-0000-4000-8000-000000008002',
    '2030-01-01 00:23:12+00'
  ),
  (
    '00000000-0000-4000-8000-000000008101',
    '00000000-0000-4000-8000-000000008001',
    '2030-01-01 00:23:12+00'
  ),
  (
    '00000000-0000-4000-8000-000000008101',
    '00000000-0000-4000-8000-000000007001',
    '2030-01-01 00:23:12+00'
  );

CREATE TEMP TABLE appointed_administrator AS
SELECT * FROM kovcheg.set_chat_administrator_for_session(
  '00000000-0000-4000-8000-000000008101',
  '00000000-0000-4000-8000-000000008203',
  '00000000-0000-4000-8000-000000007002',
  '00000000-0000-4000-8000-000000008003',
  true,
  'creator-assigned',
  2,
  '2030-01-01 00:23:13+00',
  'role-followup-assign-chat-administrator'
);

SELECT pg_temp.assert_true(
  (SELECT is_administrator FROM appointed_administrator)
  AND kovcheg.can_account_manage_chat_members(
    '00000000-0000-4000-8000-000000008003',
    '00000000-0000-4000-8000-000000008101'
  )
  AND NOT kovcheg.can_account_manage_chat_administrators(
    '00000000-0000-4000-8000-000000008003',
    '00000000-0000-4000-8000-000000008101'
  ),
  'an appointed chat administrator must remain scoped and unable to cascade administrator rights'
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
  '00000000-0000-4000-8000-000000008204',
  '00000000-0000-4000-8000-000000008003',
  repeat('W', 43),
  '2030-01-01 00:23:13+00',
  '2030-01-01 00:23:13+00',
  3600000,
  '2030-01-01 01:23:13+00',
  '2030-01-02 00:23:13+00'
);

DO $$
BEGIN
  BEGIN
    PERFORM * FROM kovcheg.set_chat_administrator_for_session(
      '00000000-0000-4000-8000-000000008101',
      '00000000-0000-4000-8000-000000008204',
      '00000000-0000-4000-8000-000000008003',
      '00000000-0000-4000-8000-000000008002',
      true,
      'cascade-denied',
      3,
      '2030-01-01 00:23:14+00',
      'role-followup-chat-administrator-cascade-denied'
    );
    RAISE EXCEPTION 'an appointed chat administrator cascaded administrator rights';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT * FROM kovcheg.set_chat_administrator_for_session(
  '00000000-0000-4000-8000-000000008101',
  '00000000-0000-4000-8000-000000008203',
  '00000000-0000-4000-8000-000000007002',
  '00000000-0000-4000-8000-000000008003',
  false,
  'creator-revoked',
  3,
  '2030-01-01 00:23:15+00',
  'role-followup-revoke-chat-administrator'
);

SELECT pg_temp.assert_true(
  kovcheg.can_account_manage_chat_administrators(
    '00000000-0000-4000-8000-000000007001',
    '00000000-0000-4000-8000-000000008101'
  )
  AND NOT kovcheg.can_account_manage_chat_administrators(
    '00000000-0000-4000-8000-000000008001',
    '00000000-0000-4000-8000-000000008101'
  )
  AND NOT kovcheg.can_account_manage_chat_administrators(
    '00000000-0000-4000-8000-000000008002',
    '00000000-0000-4000-8000-000000008101'
  ),
  'Warrior must require active membership while platform, editor, chronicler, and technical grants do not imply chat administration'
);

SELECT pg_temp.assert_true(
  NOT kovcheg.can_account_read_chat(
    '00000000-0000-4000-8000-000000007001',
    (
      SELECT id FROM kovcheg.chats
      WHERE kind = 'direct'
        AND provisioned_for_account_id = '00000000-0000-4000-8000-000000007002'
      ORDER BY id LIMIT 1
    )
  ),
  'Warrior grant must not open another account direct chat'
);

SELECT * FROM kovcheg.create_group_chat_for_session(
  '00000000-0000-4000-8000-000000008102',
  '00000000-0000-4000-8000-000000008203',
  '00000000-0000-4000-8000-000000007002',
  'creator-created',
  '2030-01-01 00:23:16+00',
  'role-followup-create-restricted-group'
);
INSERT INTO kovcheg.chat_memberships (chat_id, account_id, joined_at)
VALUES (
  '00000000-0000-4000-8000-000000008102',
  '00000000-0000-4000-8000-000000007001',
  '2030-01-01 00:23:17+00'
);
INSERT INTO kovcheg.chat_domain_capability_rules (
  chat_id, domain_status, can_read, can_write
) VALUES
  ('00000000-0000-4000-8000-000000008102', 'incubator_participant', false, false),
  ('00000000-0000-4000-8000-000000008102', 'disciple', false, false);

SELECT pg_temp.assert_true(
  kovcheg.can_account_manage_chat_administrators(
    '00000000-0000-4000-8000-000000007001',
    '00000000-0000-4000-8000-000000008102'
  )
  AND NOT kovcheg.can_account_read_chat(
    '00000000-0000-4000-8000-000000007001',
    '00000000-0000-4000-8000-000000008102'
  ),
  'scoped administration must not itself disclose chat history or content'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 4
    FROM kovcheg.audit_events
    WHERE correlation_id IN (
      'role-followup-create-group',
      'role-followup-assign-chat-administrator',
      'role-followup-revoke-chat-administrator',
      'role-followup-create-restricted-group'
    )
      AND actor_account_id = '00000000-0000-4000-8000-000000007002'
      AND details ? 'chatId'
      AND details ? 'reasonCode'
      AND details ? 'authorizationVersion'
      AND NOT details ? 'messageContent'
  ),
  'chat administration audit must record actor, target, chat, action, reason, correlation, and version without content'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.outbox_events AS event
    WHERE event.payload ? 'operatorAccountId'
      OR event.payload ? 'actorAccountId'
  ),
  'public events must not expose authenticated operator or protected audit actor identity'
);

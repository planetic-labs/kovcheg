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

INSERT INTO kovcheg.chats (
  id,
  kind,
  created_by_account_id,
  posting_policy,
  created_at
) VALUES
  (
    '00000000-0000-4000-8000-000000007101',
    'group',
    '00000000-0000-4000-8000-000000001001',
    'all_active_members',
    '2030-01-01 00:21:30+00'
  ),
  (
    '00000000-0000-4000-8000-000000007102',
    'group',
    '00000000-0000-4000-8000-000000001001',
    'all_active_members',
    '2030-01-01 00:21:30+00'
  ),
  (
    '00000000-0000-4000-8000-000000007103',
    'group',
    '00000000-0000-4000-8000-000000001001',
    'platform_roles',
    '2030-01-01 00:21:30+00'
  ),
  (
    '00000000-0000-4000-8000-000000007104',
    'direct',
    '00000000-0000-4000-8000-000000001001',
    'all_active_members',
    '2030-01-01 00:21:30+00'
  );

INSERT INTO kovcheg.chat_memberships (chat_id, account_id, role, joined_at) VALUES
  (
    '00000000-0000-4000-8000-000000007101',
    '00000000-0000-4000-8000-000000001001',
    'synthetic_system',
    '2030-01-01 00:21:30+00'
  ),
  (
    '00000000-0000-4000-8000-000000007102',
    '00000000-0000-4000-8000-000000001001',
    'synthetic_system',
    '2030-01-01 00:21:30+00'
  ),
  (
    '00000000-0000-4000-8000-000000007103',
    '00000000-0000-4000-8000-000000001001',
    'synthetic_system',
    '2030-01-01 00:21:30+00'
  ),
  (
    '00000000-0000-4000-8000-000000007103',
    '00000000-0000-4000-8000-000000001002',
    'synthetic_system',
    '2030-01-01 00:21:30+00'
  );

INSERT INTO kovcheg.chat_allowed_posting_roles (chat_id, role)
VALUES ('00000000-0000-4000-8000-000000007103', 'warrior');

INSERT INTO kovcheg.chat_domain_capability_rules (
  chat_id,
  domain_status,
  can_read,
  can_write
) VALUES
  ('00000000-0000-4000-8000-000000007101', 'incubator_participant', true, false),
  ('00000000-0000-4000-8000-000000007101', 'disciple', true, true),
  ('00000000-0000-4000-8000-000000007102', 'incubator_participant', true, true),
  ('00000000-0000-4000-8000-000000007102', 'disciple', true, false);

INSERT INTO kovcheg.messages (
  chat_id,
  sender_account_id,
  client_idempotency_key,
  content_fingerprint,
  body,
  correlation_id,
  created_at
) VALUES (
  '00000000-0000-4000-8000-000000007101',
  '00000000-0000-4000-8000-000000001001',
  'role-capability-history-001',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'Synthetic history before membership',
  'role-capability-history-001',
  '2030-01-01 00:21:31+00'
);

CREATE TEMP TABLE participant_account AS
SELECT * FROM kovcheg.admin_create_role_capable_account(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000007001',
  'role-participant@identity.invalid',
  'Role Participant',
  '2030-01-01 00:22:00+00',
  'role-capability-create-participant'
);

CREATE TEMP TABLE independent_account AS
SELECT * FROM kovcheg.admin_create_role_capable_account(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000007002',
  'role-independent@identity.invalid',
  'Role Independent',
  '2030-01-01 00:22:01+00',
  'role-capability-create-independent'
);

INSERT INTO kovcheg.chat_memberships (chat_id, account_id, joined_at)
VALUES (
  '00000000-0000-4000-8000-000000007104',
  '00000000-0000-4000-8000-000000007001',
  '2030-01-01 00:22:00+00'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_access = 'member'
      AND account_status = 'active'
      AND domain_status = 'incubator_participant'
      AND functional_grants = ARRAY[]::text[]
    FROM participant_account
  ),
  'new people must start as active ordinary accounts in the participant domain status'
);

SELECT pg_temp.assert_true(
  kovcheg.can_account_read_chat(
    '00000000-0000-4000-8000-000000007001',
    '00000000-0000-4000-8000-000000007101'
  )
  AND NOT kovcheg.can_account_post_to_chat(
    '00000000-0000-4000-8000-000000007001',
    '00000000-0000-4000-8000-000000007101'
  )
  AND kovcheg.can_account_read_chat(
    '00000000-0000-4000-8000-000000007001',
    '00000000-0000-4000-8000-000000007102'
  )
  AND kovcheg.can_account_post_to_chat(
    '00000000-0000-4000-8000-000000007001',
    '00000000-0000-4000-8000-000000007102'
  ),
  'participant read and write capabilities must follow server-configured rules'
);

SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1
    FROM kovcheg.messages
    WHERE chat_id = '00000000-0000-4000-8000-000000007101'
      AND client_idempotency_key = 'role-capability-history-001'
  )
  AND kovcheg.can_account_read_chat(
    '00000000-0000-4000-8000-000000007001',
    '00000000-0000-4000-8000-000000007101'
  ),
  'current read capability must expose history that predates membership'
);

CREATE TEMP TABLE disciple_account AS
SELECT * FROM kovcheg.admin_set_domain_status(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000007001',
  'disciple',
  'confirmed-transition',
  2,
  '2030-01-01 00:22:02+00',
  'role-capability-domain-transition'
);

SELECT pg_temp.assert_true(
  (
    SELECT domain_status = 'disciple' FROM disciple_account
  )
  AND kovcheg.can_account_post_to_chat(
    '00000000-0000-4000-8000-000000007001',
    '00000000-0000-4000-8000-000000007101'
  )
  AND kovcheg.can_account_read_chat(
    '00000000-0000-4000-8000-000000007001',
    '00000000-0000-4000-8000-000000007102'
  )
  AND NOT kovcheg.can_account_post_to_chat(
    '00000000-0000-4000-8000-000000007001',
    '00000000-0000-4000-8000-000000007102'
  ),
  'domain transition must atomically change independent read and write capabilities'
);

SELECT pg_temp.assert_true(
  (
    SELECT domain_status = 'incubator_participant'
      AND functional_grants = ARRAY[]::text[]
    FROM independent_account
  ),
  'two people must keep independent domain status and functional grants'
);

CREATE TEMP TABLE chronicler_account AS
SELECT * FROM kovcheg.admin_grant_functional_grant(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000007001',
  'chronicler',
  'explicit-assignment',
  3,
  '2030-01-01 00:22:03+00',
  'role-capability-grant-chronicler'
);

CREATE TEMP TABLE warrior_account AS
SELECT * FROM kovcheg.admin_grant_functional_grant(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000007001',
  'warrior',
  'explicit-assignment',
  4,
  '2030-01-01 00:22:04+00',
  'role-capability-grant-warrior'
);

SELECT pg_temp.assert_true(
  (SELECT functional_grants = ARRAY['chronicler'] FROM chronicler_account)
  AND (
    SELECT functional_grants @> ARRAY['chronicler', 'warrior']
    FROM warrior_account
  ),
  'chronicler must be an independent explicit grant with no automatic derivation'
);

SELECT pg_temp.assert_true(
  kovcheg.can_account_post_to_chat(
    '00000000-0000-4000-8000-000000001002',
    '00000000-0000-4000-8000-000000007103'
  )
  AND kovcheg.can_account_post_to_chat(
    '00000000-0000-4000-8000-000000001001',
    '00000000-0000-4000-8000-000000007103'
  )
  AND NOT kovcheg.can_account_post_to_chat(
    '00000000-0000-4000-8000-000000001001',
    '00000000-0000-4000-8000-000000007104'
  ),
  'Master must match Warrior group posting without foreign direct-chat access'
);

DO $$
BEGIN
  BEGIN
    PERFORM * FROM kovcheg.admin_set_domain_status(
      repeat('o', 43),
      '00000000-0000-4000-8000-000000007002',
      'disciple',
      'unauthorized-transition',
      2,
      '2030-01-01 00:22:05+00',
      'role-capability-denied-transition'
    );
    RAISE EXCEPTION 'an ordinary session changed another account domain status';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT domain_status = 'incubator_participant'
    FROM kovcheg.read_role_capable_account(
      '00000000-0000-4000-8000-000000007002'
    )
  ),
  'unauthorized transition must fail without partial state'
);

CREATE TEMP TABLE revoked_chronicler_account AS
SELECT * FROM kovcheg.admin_revoke_functional_grant(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000007001',
  'chronicler',
  'explicit-revocation',
  5,
  '2030-01-01 00:22:06+00',
  'role-capability-revoke-chronicler'
);

SELECT pg_temp.assert_true(
  (
    SELECT functional_grants = ARRAY['warrior'] FROM revoked_chronicler_account
  ),
  'functional grant revocation must preserve independent grants'
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
  '00000000-0000-4000-8000-000000007201',
  '00000000-0000-4000-8000-000000007001',
  repeat('j', 43),
  '2030-01-01 00:22:00+00',
  '2030-01-01 00:22:00+00',
  3600000,
  '2030-01-01 01:22:00+00',
  '2030-01-02 00:22:00+00'
);

SELECT pg_temp.assert_true(
  (
    SELECT principal @> pg_catalog.jsonb_build_object(
      'contractVersion', 2,
      'accountAccess', 'member',
      'accountStatus', 'active',
      'sessionStatus', 'active',
      'domainStatus', 'disciple',
      'functionalGrants', pg_catalog.jsonb_build_array('warrior')
    )
      AND principal -> 'administrativeCapabilities' = pg_catalog.jsonb_build_object(
        'canManageAccounts', false,
        'canManageDomainStatus', false,
        'canManageFunctionalGrants', false,
        'canManagePlatformAdministrators', false
      )
      AND principal -> 'diagnosticCapabilities' = pg_catalog.jsonb_build_object(
        'canReadHealthAndReadiness', false,
        'canReadBuildAndMigrationVersions', false,
        'canReadQueueAndTechnicalState', false,
        'canReadSanitizedDiagnostics', false
      )
      AND principal -> 'materialCapabilities' = '[]'::jsonb
      AND principal -> 'sensitiveCapabilities' = pg_catalog.jsonb_build_object(
        'canPerformSensitiveActions', false
      )
    FROM (
      SELECT kovcheg.read_current_principal_authorization(
        repeat('j', 43),
        '2030-01-01 00:22:07+00',
        false
      ) AS principal
    ) AS readback
  ),
  'current principal readback must be versioned and server authoritative'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 4
    FROM kovcheg.audit_events
    WHERE actor_account_id = '00000000-0000-4000-8000-000000003001'
      AND target_id = '00000000-0000-4000-8000-000000007001'
      AND action IN (
        'authorization.domain-status-set',
        'authorization.functional-grant.granted',
        'authorization.functional-grant.revoked'
      )
      AND details ? 'reasonCode'
      AND details ? 'authorizationVersion'
  ),
  'protected audit must record actor, target, previous/new state, reason, and version'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.outbox_events AS event
    WHERE event.payload ? 'operatorAccountId'
      OR event.payload ? 'actorAccountId'
  ),
  'public outbox payloads must not expose the authenticated operator or audit actor'
);

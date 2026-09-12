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
  kovcheg.current_migration_version() = '0018'
  AND (SELECT count(*) = 18 FROM kovcheg_meta.schema_migrations),
  'the complete eighteen-migration account and passkey management chain must be recorded'
);

DO $$
DECLARE
  protected_function regprocedure;
BEGIN
  FOREACH protected_function IN ARRAY ARRAY[
    'kovcheg.admin_list_role_capable_accounts(text,uuid,integer,timestamp with time zone)'::regprocedure,
    'kovcheg.admin_read_role_capable_account(text,uuid,timestamp with time zone)'::regprocedure,
    'kovcheg.read_own_auth_passkey_settings(text,timestamp with time zone)'::regprocedure,
    'kovcheg.revoke_own_auth_passkey(text,uuid,timestamp with time zone,character varying)'::regprocedure
  ] LOOP
    PERFORM pg_temp.assert_true(
      has_function_privilege('kovcheg_auth_runtime', protected_function, 'EXECUTE')
      AND has_function_privilege('kovcheg_auth_app', protected_function, 'EXECUTE')
      AND NOT has_function_privilege('kovcheg_runtime', protected_function, 'EXECUTE')
      AND NOT has_function_privilege('kovcheg_app', protected_function, 'EXECUTE')
      AND NOT has_function_privilege('kovcheg_audit', protected_function, 'EXECUTE')
      AND NOT has_function_privilege('kovcheg_audit_writer', protected_function, 'EXECUTE')
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS procedure
        CROSS JOIN LATERAL pg_catalog.aclexplode(
          COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
        ) AS privilege
        WHERE procedure.oid = protected_function
          AND privilege.grantee = 0
          AND privilege.privilege_type = 'EXECUTE'
      )
      AND (
        SELECT procedure.prosecdef
          AND procedure.proconfig = ARRAY['search_path=pg_catalog, kovcheg']
          AND owner.rolname = 'kovcheg_migration'
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
        WHERE procedure.oid = protected_function
      ),
      'account and own-passkey functions must preserve fixed-search-path least privilege'
    );
  END LOOP;
END;
$$;

SELECT pg_temp.assert_true(
  NOT has_function_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.require_active_auth_administrator_for_target(text,uuid,timestamp with time zone)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    'kovcheg_auth_app',
    'kovcheg.require_active_auth_administrator_for_target(text,uuid,timestamp with time zone)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    'kovcheg_runtime',
    'kovcheg.require_active_auth_administrator_for_target(text,uuid,timestamp with time zone)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    'kovcheg_app',
    'kovcheg.require_active_auth_administrator_for_target(text,uuid,timestamp with time zone)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    'kovcheg_audit_writer',
    'kovcheg.require_active_auth_administrator_for_target(text,uuid,timestamp with time zone)',
    'EXECUTE'
  )
  AND (
    SELECT NOT procedure.prosecdef
      AND procedure.proconfig = ARRAY['search_path=pg_catalog, kovcheg']
      AND owner.rolname = 'kovcheg_migration'
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
        ) AS privilege
        WHERE privilege.grantee = 0
          AND privilege.privilege_type = 'EXECUTE'
      )
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
    WHERE procedure.oid =
      'kovcheg.require_active_auth_administrator_for_target(text,uuid,timestamp with time zone)'::regprocedure
  ),
  'the target-aware administrator guard must remain private and fixed-search-path'
);

SELECT pg_temp.assert_true(
  NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.account_auth_profiles',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.account_domain_statuses',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.auth_passkey_credentials',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.audit_events',
    'SELECT,INSERT,UPDATE,DELETE'
  ),
  'the new surface must not add auth runtime table access'
);

SELECT pg_temp.assert_true(
  (
    SELECT ever_added
      AND active_passkey_count = 0
      AND active_passkeys = '[]'::jsonb
    FROM kovcheg.read_own_auth_passkey_settings(
      repeat('P', 42) || '8',
      '2030-01-01 00:31:01+00'
    )
  )
  AND (
    SELECT revoked_at = '2030-01-01 00:31:00+00'::timestamptz
    FROM kovcheg.auth_passkey_credentials
    WHERE id = '00000000-0000-4000-8000-000000018203'
  )
  AND (
    SELECT count(*) = 1
      AND bool_and(actor_account_id = '00000000-0000-4000-8000-000000018001')
      AND bool_and(migration_version = '0018')
      AND bool_and(target_type = 'auth_passkey_credential')
      AND bool_and(target_id = '00000000-0000-4000-8000-000000018203')
      AND bool_and(outcome = 'success')
      AND bool_and(details = '{"remainingActiveCount": 0}'::jsonb)
    FROM kovcheg.audit_events
    WHERE correlation_id = 'own-passkey-revoke-race'
      AND action = 'auth.passkey.revoked'
  ),
  'concurrent final-key revocation must keep ever-added state and one sanitized audit event'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 2
    FROM kovcheg.audit_events
    WHERE action = 'auth.passkey.revoked'
      AND correlation_id IN ('own-passkey-revoke-one', 'own-passkey-revoke-two')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events
    WHERE correlation_id IN (
      'own-passkey-revoke-one-retry',
      'own-passkey-foreign-revoke'
    )
  ),
  'only effective owned revocations must append one audit event each'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events AS event
    WHERE event.action = 'auth.passkey.revoked'
      AND (
        NOT kovcheg.event_metadata_is_sanitized(event.details)
        OR event.details::text ~* '(email|otp|token|cookie|secret|code|verifier|contact|credential|public.?key)'
        OR event.details::text LIKE '%@%'
        OR event.details::text LIKE '%.invalid%'
        OR event.details::text ~ '[A-Za-z0-9_-]{43}'
      )
  ),
  'passkey revocation audit must contain only the remaining active count'
);

INSERT INTO kovcheg.chats (
  id,
  kind,
  created_by_account_id,
  posting_policy,
  created_at
) VALUES (
  '00000000-0000-4000-8000-000000018401',
  'group',
  '00000000-0000-4000-8000-000000001001',
  'all_active_members',
  '2030-01-01 00:31:10+00'
);

INSERT INTO kovcheg.chat_memberships (chat_id, account_id, joined_at)
VALUES (
  '00000000-0000-4000-8000-000000018401',
  '00000000-0000-4000-8000-000000018001',
  '2030-01-01 00:31:10+00'
);

INSERT INTO kovcheg.chat_domain_capability_rules (
  chat_id,
  domain_status,
  can_read,
  can_write
) VALUES
  (
    '00000000-0000-4000-8000-000000018401',
    'incubator_participant',
    true,
    true
  ),
  (
    '00000000-0000-4000-8000-000000018401',
    'disciple',
    false,
    false
  );

CREATE TEMP TABLE account_domain_transition AS
SELECT *
FROM kovcheg.admin_set_domain_status(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000018001',
  'disciple',
  'account-management-readback',
  2,
  '2030-01-01 00:31:11+00',
  'account-management-domain-revoke-membership'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000018001'
      AND email = 'settings-member@auth.invalid'
      AND display_name = 'Settings Member'
      AND account_status = 'active'
      AND domain_status = 'disciple'
      AND functional_grants = ARRAY[]::text[]
    FROM account_domain_transition
  )
  AND (
    SELECT authorization_version = 2
      AND domain_status = 'disciple'
    FROM kovcheg.admin_read_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000018001',
      '2030-01-01 00:31:12+00'
    )
  )
  AND (
    SELECT status = 'revoked'
      AND revoked_at = '2030-01-01 00:31:11+00'::timestamptz
    FROM kovcheg.chat_memberships
    WHERE chat_id = '00000000-0000-4000-8000-000000018401'
      AND account_id = '00000000-0000-4000-8000-000000018001'
  )
  AND (
    SELECT revoked_at IS NULL
    FROM kovcheg.auth_sessions
    WHERE id = '00000000-0000-4000-8000-000000018102'
  )
  AND (
    SELECT ever_added
      AND active_passkey_count = 0
      AND active_passkeys = '[]'::jsonb
    FROM kovcheg.read_own_auth_passkey_settings(
      repeat('P', 42) || '8',
      '2030-01-01 00:31:12+00'
    )
  ),
  'domain transition must revoke denied chat membership without losing account, version, session, or passkey state'
);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM kovcheg.accounts
    WHERE id = '00000000-0000-4000-8000-000000018917'
  ) THEN
    PERFORM pg_temp.assert_true(
      (
        SELECT profile.email = 'upgrade-v17@auth.invalid'
          AND account.status = 'active'
          AND session.revoked_at IS NULL
          AND passkey.revoked_at IS NULL
          AND passkey.created_at = '2030-01-01 00:17:00+00'::timestamptz
        FROM kovcheg.account_auth_profiles AS profile
        JOIN kovcheg.accounts AS account ON account.id = profile.account_id
        JOIN kovcheg.auth_sessions AS session ON session.account_id = account.id
        JOIN kovcheg.auth_passkey_credentials AS passkey
          ON passkey.account_id = account.id
        WHERE account.id = '00000000-0000-4000-8000-000000018917'
      )
      AND (
        SELECT ever_added
          AND active_passkey_count = 1
          AND active_passkeys -> 0 ->> 'id' =
            '00000000-0000-4000-8000-000000018919'
        FROM kovcheg.read_own_auth_passkey_settings(
          repeat('P', 42) || '7',
          '2030-01-01 00:17:01+00'
        )
      ),
      'the additive migration must preserve the v17 account, session, and passkey bytes'
    );
  END IF;
END;
$$;

BEGIN;

INSERT INTO kovcheg.accounts (
  id, kind, status, created_at, activated_at
) VALUES (
  '00000000-0000-4000-8000-000000018801',
  'person',
  'active',
  '2030-01-01 00:32:00+00',
  '2030-01-01 00:32:00+00'
);
INSERT INTO kovcheg.account_auth_profiles (
  account_id, email, display_name, auth_role, created_at, updated_at
) VALUES (
  '00000000-0000-4000-8000-000000018801',
  'rollback-owner@auth.invalid',
  'Rollback Owner',
  'student',
  '2030-01-01 00:32:00+00',
  '2030-01-01 00:32:00+00'
);
INSERT INTO kovcheg.account_domain_statuses (
  account_id, domain_status, authorization_version, changed_at
) VALUES (
  '00000000-0000-4000-8000-000000018801',
  'incubator_participant',
  1,
  '2030-01-01 00:32:00+00'
);
INSERT INTO kovcheg.auth_sessions (
  id, account_id, token_verifier, issued_at, last_seen_at,
  idle_lifetime_ms, idle_expires_at, absolute_expires_at
) VALUES (
  '00000000-0000-4000-8000-000000018802',
  '00000000-0000-4000-8000-000000018801',
  repeat('P', 42) || '9',
  '2030-01-01 00:32:00+00',
  '2030-01-01 00:32:00+00',
  3600000,
  '2030-01-01 01:32:00+00',
  '2030-01-02 00:32:00+00'
);
INSERT INTO kovcheg.auth_passkey_credentials (
  id, account_id, credential_id, public_key, sign_count, transports,
  aaguid, attestation_format, registered_backup_eligible,
  registered_backup_state, last_backup_eligible, last_backup_state,
  created_by_session_id, registration_correlation_id, created_at
) VALUES (
  '00000000-0000-4000-8000-000000018803',
  '00000000-0000-4000-8000-000000018801',
  decode(repeat('f1', 32), 'hex'),
  decode(repeat('f2', 64), 'hex'),
  0,
  ARRAY['internal']::kovcheg.auth_passkey_transport[],
  '00000000-0000-4000-8000-000000018804',
  'none',
  false,
  false,
  false,
  false,
  '00000000-0000-4000-8000-000000018802',
  'own-passkey-rollback-register',
  '2030-01-01 00:32:00+00'
);

CREATE FUNCTION pg_temp.reject_own_passkey_audit_fixture()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.correlation_id = 'own-passkey-revoke-rollback' THEN
    RAISE EXCEPTION 'synthetic own passkey audit failure';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER reject_own_passkey_audit_fixture
BEFORE INSERT ON kovcheg.audit_events
FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_own_passkey_audit_fixture();

DO $$
BEGIN
  BEGIN
    PERFORM kovcheg.revoke_own_auth_passkey(
      repeat('P', 42) || '9',
      '00000000-0000-4000-8000-000000018803',
      '2030-01-01 00:32:01+00',
      'own-passkey-revoke-rollback'
    );
    RAISE EXCEPTION 'a rejected audit did not roll back passkey revocation';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'synthetic own passkey audit failure' THEN
      RAISE;
    END IF;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT revoked_at IS NULL
    FROM kovcheg.auth_passkey_credentials
    WHERE id = '00000000-0000-4000-8000-000000018803'
  )
  AND NOT EXISTS (
    SELECT 1 FROM kovcheg.audit_events
    WHERE correlation_id = 'own-passkey-revoke-rollback'
  ),
  'audit failure must roll back the passkey mutation without partial evidence'
);

ROLLBACK;

BEGIN;

SELECT * FROM kovcheg.admin_create_role_capable_account(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000018851',
  'owner-boundary-delegated@auth.invalid',
  'Owner Boundary Delegated Administrator',
  '2030-01-01 00:33:00+00',
  'owner-boundary-create-delegated'
);
SELECT * FROM kovcheg.admin_grant_functional_grant(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000018851',
  'platform_administrator',
  'owner-delegated',
  2,
  '2030-01-01 00:33:01+00',
  'owner-boundary-grant-delegated'
);

INSERT INTO kovcheg.auth_sessions (
  id, account_id, token_verifier, issued_at, last_seen_at,
  idle_lifetime_ms, idle_expires_at, absolute_expires_at
) VALUES (
  '00000000-0000-4000-8000-000000018861',
  '00000000-0000-4000-8000-000000018851',
  repeat('D', 42) || '8',
  '2030-01-01 00:33:01+00',
  '2030-01-01 00:33:01+00',
  3600000,
  '2030-01-01 01:33:01+00',
  '2030-01-02 00:33:01+00'
);

SELECT * FROM kovcheg.admin_create_role_capable_account(
  repeat('D', 42) || '8',
  '00000000-0000-4000-8000-000000018852',
  'owner-boundary-target@auth.invalid',
  'Owner Boundary Ordinary Target',
  '2030-01-01 00:33:02+00',
  'owner-boundary-create-target'
);
SELECT * FROM kovcheg.admin_create_role_capable_account(
  repeat('D', 42) || '8',
  '00000000-0000-4000-8000-000000018853',
  'owner-boundary-technical@auth.invalid',
  'Owner Boundary Technical Administrator',
  '2030-01-01 00:33:03+00',
  'owner-boundary-create-technical'
);
SELECT * FROM kovcheg.admin_grant_functional_grant(
  repeat('D', 42) || '8',
  '00000000-0000-4000-8000-000000018853',
  'technical_administrator',
  'delegated-assignment',
  2,
  '2030-01-01 00:33:04+00',
  'owner-boundary-grant-technical'
);
SELECT * FROM kovcheg.admin_create_role_capable_account(
  repeat('D', 42) || '8',
  '00000000-0000-4000-8000-000000018854',
  'owner-boundary-ordinary@auth.invalid',
  'Owner Boundary Ordinary Actor',
  '2030-01-01 00:33:05+00',
  'owner-boundary-create-ordinary'
);

INSERT INTO kovcheg.auth_sessions (
  id, account_id, token_verifier, issued_at, last_seen_at,
  idle_lifetime_ms, idle_expires_at, absolute_expires_at
) VALUES
  (
    '00000000-0000-4000-8000-000000018862',
    '00000000-0000-4000-8000-000000018852',
    repeat('D', 42) || '7',
    '2030-01-01 00:33:05+00',
    '2030-01-01 00:33:05+00',
    3600000,
    '2030-01-01 01:33:05+00',
    '2030-01-02 00:33:05+00'
  ),
  (
    '00000000-0000-4000-8000-000000018863',
    '00000000-0000-4000-8000-000000018853',
    repeat('D', 42) || '6',
    '2030-01-01 00:33:05+00',
    '2030-01-01 00:33:05+00',
    3600000,
    '2030-01-01 01:33:05+00',
    '2030-01-02 00:33:05+00'
  ),
  (
    '00000000-0000-4000-8000-000000018864',
    '00000000-0000-4000-8000-000000018854',
    repeat('D', 42) || '5',
    '2030-01-01 00:33:05+00',
    '2030-01-01 00:33:05+00',
    3600000,
    '2030-01-01 01:33:05+00',
    '2030-01-02 00:33:05+00'
  );

UPDATE kovcheg.auth_email_challenges AS challenge
SET invalidated_at = GREATEST('2030-01-01 00:34:00+00', challenge.issued_at)
WHERE challenge.account_id = '00000000-0000-4000-8000-000000003001'
  AND challenge.used_at IS NULL
  AND challenge.invalidated_at IS NULL;

INSERT INTO kovcheg.auth_email_challenges (
  id, account_id, code_verifier, issued_at, expires_at, max_attempts
) VALUES (
  '00000000-0000-4000-8000-000000018871',
  '00000000-0000-4000-8000-000000003001',
  repeat('D', 42) || '4',
  '2030-01-01 00:34:00+00',
  '2030-01-01 00:44:00+00',
  5
);

INSERT INTO kovcheg.auth_passkey_credentials (
  id, account_id, credential_id, public_key, sign_count, transports,
  aaguid, attestation_format, registered_backup_eligible,
  registered_backup_state, last_backup_eligible, last_backup_state,
  created_by_session_id, registration_correlation_id, created_at
) VALUES (
  '00000000-0000-4000-8000-000000018872',
  '00000000-0000-4000-8000-000000003001',
  decode(repeat('d8', 32), 'hex'),
  decode(repeat('d9', 64), 'hex'),
  0,
  ARRAY['internal']::kovcheg.auth_passkey_transport[],
  '00000000-0000-4000-8000-000000018873',
  'none',
  false,
  false,
  false,
  false,
  '00000000-0000-4000-8000-000000003091',
  'owner-boundary-passkey-fixture',
  '2030-01-01 00:34:00+00'
);

SELECT * FROM kovcheg.admin_update_auth_account(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000003001',
  'synthetic-administrator@auth.invalid',
  'Synthetic Administrator',
  '2030-01-01 00:34:01+00',
  'owner-boundary-self-update'
);
SELECT * FROM kovcheg.admin_set_auth_account_status(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000003001',
  'active',
  '2030-01-01 00:34:02+00',
  'owner-boundary-self-status'
);
SELECT * FROM kovcheg.admin_set_domain_status(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000003001',
  (
    SELECT domain_status
    FROM kovcheg.account_domain_statuses
    WHERE account_id = '00000000-0000-4000-8000-000000003001'
  ),
  'owner-self-update',
  (
    SELECT authorization_version + 1
    FROM kovcheg.account_domain_statuses
    WHERE account_id = '00000000-0000-4000-8000-000000003001'
  ),
  '2030-01-01 00:34:03+00',
  'owner-boundary-self-domain'
);
SELECT * FROM kovcheg.admin_grant_functional_grant(
  repeat('m', 43),
  '00000000-0000-4000-8000-000000003001',
  'editor',
  'owner-self-update',
  (
    SELECT authorization_version + 1
    FROM kovcheg.account_domain_statuses
    WHERE account_id = '00000000-0000-4000-8000-000000003001'
  ),
  '2030-01-01 00:34:04+00',
  'owner-boundary-self-grant'
);

CREATE FUNCTION pg_temp.owner_boundary_state()
RETURNS jsonb
LANGUAGE sql
STABLE
AS $$
  SELECT pg_catalog.jsonb_build_object(
    'account', (
      SELECT pg_catalog.to_jsonb(account)
      FROM kovcheg.accounts AS account
      WHERE account.id = '00000000-0000-4000-8000-000000003001'
    ),
    'profile', (
      SELECT pg_catalog.to_jsonb(profile)
      FROM kovcheg.account_auth_profiles AS profile
      WHERE profile.account_id = '00000000-0000-4000-8000-000000003001'
    ),
    'domain', (
      SELECT pg_catalog.to_jsonb(domain)
      FROM kovcheg.account_domain_statuses AS domain
      WHERE domain.account_id = '00000000-0000-4000-8000-000000003001'
    ),
    'roles', (
      SELECT COALESCE(
        pg_catalog.jsonb_agg(pg_catalog.to_jsonb(role) ORDER BY role.role),
        '[]'::jsonb
      )
      FROM kovcheg.account_platform_roles AS role
      WHERE role.account_id = '00000000-0000-4000-8000-000000003001'
    ),
    'sessions', (
      SELECT COALESCE(
        pg_catalog.jsonb_agg(pg_catalog.to_jsonb(session) ORDER BY session.id),
        '[]'::jsonb
      )
      FROM kovcheg.auth_sessions AS session
      WHERE session.account_id = '00000000-0000-4000-8000-000000003001'
    ),
    'challenges', (
      SELECT COALESCE(
        pg_catalog.jsonb_agg(pg_catalog.to_jsonb(challenge) ORDER BY challenge.id),
        '[]'::jsonb
      )
      FROM kovcheg.auth_email_challenges AS challenge
      WHERE challenge.account_id = '00000000-0000-4000-8000-000000003001'
    ),
    'passkeys', (
      SELECT COALESCE(
        pg_catalog.jsonb_agg(pg_catalog.to_jsonb(passkey) ORDER BY passkey.id),
        '[]'::jsonb
      )
      FROM kovcheg.auth_passkey_credentials AS passkey
      WHERE passkey.account_id = '00000000-0000-4000-8000-000000003001'
    )
  );
$$;

CREATE TEMP TABLE owner_boundary_snapshot AS
SELECT pg_temp.owner_boundary_state() AS state;

DO $$
BEGIN
  BEGIN
    PERFORM * FROM kovcheg.admin_update_auth_account(
      repeat('D', 42) || '8',
      '00000000-0000-4000-8000-000000003001',
      'owner-boundary-denied@auth.invalid',
      'Denied Owner Update',
      '2030-01-01 00:35:00+00',
      'owner-boundary-denied-update'
    );
    RAISE EXCEPTION 'delegated administrator changed the server owner profile';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM * FROM kovcheg.admin_set_auth_account_status(
      repeat('D', 42) || '8',
      '00000000-0000-4000-8000-000000003001',
      'deactivated',
      '2030-01-01 00:35:01+00',
      'owner-boundary-denied-status'
    );
    RAISE EXCEPTION 'delegated administrator changed the server owner status';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM * FROM kovcheg.admin_set_domain_status(
      repeat('D', 42) || '8',
      '00000000-0000-4000-8000-000000003001',
      'disciple',
      'owner-target-denied',
      (
        SELECT authorization_version + 1
        FROM kovcheg.account_domain_statuses
        WHERE account_id = '00000000-0000-4000-8000-000000003001'
      ),
      '2030-01-01 00:35:02+00',
      'owner-boundary-denied-domain'
    );
    RAISE EXCEPTION 'delegated administrator changed the server owner domain';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM * FROM kovcheg.admin_grant_functional_grant(
      repeat('D', 42) || '8',
      '00000000-0000-4000-8000-000000003001',
      'chronicler',
      'owner-target-denied',
      (
        SELECT authorization_version + 1
        FROM kovcheg.account_domain_statuses
        WHERE account_id = '00000000-0000-4000-8000-000000003001'
      ),
      '2030-01-01 00:35:03+00',
      'owner-boundary-denied-grant'
    );
    RAISE EXCEPTION 'delegated administrator changed a server owner grant';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM kovcheg.admin_revoke_auth_session(
      repeat('D', 42) || '8',
      '00000000-0000-4000-8000-000000003001',
      '00000000-0000-4000-8000-000000003091',
      '2030-01-01 00:35:04+00',
      'owner-boundary-denied-session'
    );
    RAISE EXCEPTION 'delegated administrator revoked a server owner session';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM kovcheg.admin_revoke_all_auth_sessions(
      repeat('D', 42) || '8',
      '00000000-0000-4000-8000-000000003001',
      '2030-01-01 00:35:05+00',
      'owner-boundary-denied-sessions'
    );
    RAISE EXCEPTION 'delegated administrator revoked all server owner sessions';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM kovcheg.admin_security_reset_auth_access(
      repeat('D', 42) || '8',
      '00000000-0000-4000-8000-000000003001',
      '2030-01-01 00:35:06+00',
      'owner-boundary-denied-security-reset'
    );
    RAISE EXCEPTION 'delegated administrator reset the server owner authentication';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM * FROM kovcheg.admin_update_auth_account(
      repeat('D', 42) || '5',
      '00000000-0000-4000-8000-000000003001',
      'owner-boundary-ordinary-denied@auth.invalid',
      'Ordinary Actor Denied',
      '2030-01-01 00:35:07+00',
      'owner-boundary-ordinary-denied'
    );
    RAISE EXCEPTION 'ordinary account changed the server owner';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM * FROM kovcheg.admin_update_auth_account(
      repeat('D', 42) || '6',
      '00000000-0000-4000-8000-000000003001',
      'owner-boundary-technical-denied@auth.invalid',
      'Technical Actor Denied',
      '2030-01-01 00:35:08+00',
      'owner-boundary-technical-denied'
    );
    RAISE EXCEPTION 'technical administrator changed the server owner';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT snapshot.state = pg_temp.owner_boundary_state()
    FROM owner_boundary_snapshot AS snapshot
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events AS event
    WHERE event.correlation_id IN (
      'owner-boundary-denied-update',
      'owner-boundary-denied-status',
      'owner-boundary-denied-domain',
      'owner-boundary-denied-grant',
      'owner-boundary-denied-session',
      'owner-boundary-denied-sessions',
      'owner-boundary-denied-security-reset',
      'owner-boundary-ordinary-denied',
      'owner-boundary-technical-denied'
    )
  ),
  'denied owner-target mutations must leave identity, access, credentials, sessions, challenges, and audit unchanged'
);

DO $$
DECLARE
  probe_succeeded boolean;
BEGIN
  probe_succeeded := false;
  BEGIN
    PERFORM kovcheg.admin_revoke_auth_session(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003001',
      '00000000-0000-4000-8000-000000003091',
      '2030-01-01 00:36:00+00',
      'owner-boundary-self-session-probe'
    );
    probe_succeeded := true;
    RAISE EXCEPTION 'rollback owner single-session probe';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'rollback owner single-session probe' THEN RAISE; END IF;
  END;
  IF NOT probe_succeeded THEN RAISE EXCEPTION 'server owner single-session probe failed'; END IF;

  probe_succeeded := false;
  BEGIN
    PERFORM kovcheg.admin_revoke_all_auth_sessions(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003001',
      '2030-01-01 00:36:01+00',
      'owner-boundary-self-sessions-probe'
    );
    probe_succeeded := true;
    RAISE EXCEPTION 'rollback owner all-sessions probe';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'rollback owner all-sessions probe' THEN RAISE; END IF;
  END;
  IF NOT probe_succeeded THEN RAISE EXCEPTION 'server owner all-sessions probe failed'; END IF;

  probe_succeeded := false;
  BEGIN
    PERFORM * FROM kovcheg.admin_set_auth_account_status(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003001',
      'deactivated',
      '2030-01-01 00:36:02+00',
      'owner-boundary-self-deactivation-probe'
    );
    probe_succeeded := true;
    RAISE EXCEPTION 'rollback owner deactivation probe';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'rollback owner deactivation probe' THEN RAISE; END IF;
  END;
  IF NOT probe_succeeded THEN RAISE EXCEPTION 'server owner deactivation probe failed'; END IF;

  probe_succeeded := false;
  BEGIN
    PERFORM kovcheg.admin_security_reset_auth_access(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003001',
      '2030-01-01 00:36:03+00',
      'owner-boundary-self-security-reset-probe'
    );
    probe_succeeded := true;
    RAISE EXCEPTION 'rollback owner security-reset probe';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'rollback owner security-reset probe' THEN RAISE; END IF;
  END;
  IF NOT probe_succeeded THEN RAISE EXCEPTION 'server owner security-reset probe failed'; END IF;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT snapshot.state = pg_temp.owner_boundary_state()
    FROM owner_boundary_snapshot AS snapshot
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events AS event
    WHERE event.correlation_id IN (
      'owner-boundary-self-session-probe',
      'owner-boundary-self-sessions-probe',
      'owner-boundary-self-deactivation-probe',
      'owner-boundary-self-security-reset-probe'
    )
  ),
  'server owner self-operations must remain authorized and fully rollback-safe'
);

INSERT INTO kovcheg.auth_email_challenges (
  id, account_id, code_verifier, issued_at, expires_at, max_attempts
) VALUES (
  '00000000-0000-4000-8000-000000018874',
  '00000000-0000-4000-8000-000000018852',
  repeat('D', 42) || '3',
  '2030-01-01 00:37:00+00',
  '2030-01-01 00:47:00+00',
  5
);
INSERT INTO kovcheg.auth_passkey_credentials (
  id, account_id, credential_id, public_key, sign_count, transports,
  aaguid, attestation_format, registered_backup_eligible,
  registered_backup_state, last_backup_eligible, last_backup_state,
  created_by_session_id, registration_correlation_id, created_at
) VALUES (
  '00000000-0000-4000-8000-000000018875',
  '00000000-0000-4000-8000-000000018852',
  decode(repeat('da', 32), 'hex'),
  decode(repeat('db', 64), 'hex'),
  0,
  ARRAY['internal']::kovcheg.auth_passkey_transport[],
  '00000000-0000-4000-8000-000000018876',
  'none',
  false,
  false,
  false,
  false,
  '00000000-0000-4000-8000-000000018862',
  'owner-boundary-target-passkey',
  '2030-01-01 00:37:00+00'
);

SELECT * FROM kovcheg.admin_update_auth_account(
  repeat('D', 42) || '8',
  '00000000-0000-4000-8000-000000018852',
  'owner-boundary-target-updated@auth.invalid',
  'Owner Boundary Target Updated',
  '2030-01-01 00:37:01+00',
  'owner-boundary-ordinary-update'
);
SELECT * FROM kovcheg.admin_set_domain_status(
  repeat('D', 42) || '8',
  '00000000-0000-4000-8000-000000018852',
  'disciple',
  'ordinary-target-update',
  2,
  '2030-01-01 00:37:02+00',
  'owner-boundary-ordinary-domain'
);
SELECT * FROM kovcheg.admin_grant_functional_grant(
  repeat('D', 42) || '8',
  '00000000-0000-4000-8000-000000018852',
  'editor',
  'ordinary-target-update',
  3,
  '2030-01-01 00:37:03+00',
  'owner-boundary-ordinary-grant'
);
SELECT pg_temp.assert_true(
  kovcheg.admin_revoke_auth_session(
    repeat('D', 42) || '8',
    '00000000-0000-4000-8000-000000018852',
    '00000000-0000-4000-8000-000000018862',
    '2030-01-01 00:37:04+00',
    'owner-boundary-ordinary-session'
  ),
  'delegated administration must still revoke one ordinary target session'
);

INSERT INTO kovcheg.auth_sessions (
  id, account_id, token_verifier, issued_at, last_seen_at,
  idle_lifetime_ms, idle_expires_at, absolute_expires_at
) VALUES (
  '00000000-0000-4000-8000-000000018865',
  '00000000-0000-4000-8000-000000018852',
  repeat('D', 42) || '2',
  '2030-01-01 00:37:04+00',
  '2030-01-01 00:37:04+00',
  3600000,
  '2030-01-01 01:37:04+00',
  '2030-01-02 00:37:04+00'
);

SELECT pg_temp.assert_true(
  kovcheg.admin_revoke_all_auth_sessions(
    repeat('D', 42) || '8',
    '00000000-0000-4000-8000-000000018852',
    '2030-01-01 00:37:05+00',
    'owner-boundary-ordinary-sessions'
  ) = 1,
  'delegated administration must still revoke all ordinary target sessions'
);
SELECT pg_temp.assert_true(
  kovcheg.admin_security_reset_auth_access(
    repeat('D', 42) || '8',
    '00000000-0000-4000-8000-000000018852',
    '2030-01-01 00:37:06+00',
    'owner-boundary-ordinary-security-reset'
  ) @> pg_catalog.jsonb_build_object(
    'revokedPasskeyCount', 1,
    'invalidatedChallengeCount', 1,
    'revokedApplicationSessionCount', 0
  ),
  'delegated administration must still security-reset an ordinary target'
);
SELECT * FROM kovcheg.admin_set_auth_account_status(
  repeat('D', 42) || '8',
  '00000000-0000-4000-8000-000000018852',
  'deactivated',
  '2030-01-01 00:37:07+00',
  'owner-boundary-ordinary-status'
);

SELECT pg_temp.assert_true(
  (
    SELECT profile.email = 'owner-boundary-target-updated@auth.invalid'
      AND profile.display_name = 'Owner Boundary Target Updated'
      AND account.status = 'deactivated'
      AND domain.domain_status = 'disciple'
      AND domain.authorization_version = 3
      AND passkey.revoked_at = '2030-01-01 00:37:06+00'::timestamptz
      AND challenge.invalidated_at = '2030-01-01 00:37:06+00'::timestamptz
    FROM kovcheg.account_auth_profiles AS profile
    JOIN kovcheg.accounts AS account ON account.id = profile.account_id
    JOIN kovcheg.account_domain_statuses AS domain ON domain.account_id = account.id
    JOIN kovcheg.auth_passkey_credentials AS passkey ON passkey.account_id = account.id
    JOIN kovcheg.auth_email_challenges AS challenge ON challenge.account_id = account.id
    WHERE account.id = '00000000-0000-4000-8000-000000018852'
  )
  AND EXISTS (
    SELECT 1
    FROM kovcheg.account_platform_roles AS role
    WHERE role.account_id = '00000000-0000-4000-8000-000000018852'
      AND role.role = 'editor'
  )
  AND (
    SELECT count(*) = 7
      AND bool_and(actor_account_id = '00000000-0000-4000-8000-000000018851')
      AND bool_and(target_id = '00000000-0000-4000-8000-000000018852')
      AND bool_and(outcome = 'success')
    FROM kovcheg.audit_events
    WHERE correlation_id IN (
      'owner-boundary-ordinary-update',
      'owner-boundary-ordinary-domain',
      'owner-boundary-ordinary-grant',
      'owner-boundary-ordinary-session',
      'owner-boundary-ordinary-sessions',
      'owner-boundary-ordinary-security-reset',
      'owner-boundary-ordinary-status'
    )
  ),
  'all seven delegated operations must retain their existing ordinary-account behavior and sanitized audit'
);

ROLLBACK;

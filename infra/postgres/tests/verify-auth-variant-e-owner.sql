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
  kovcheg.current_migration_version() = '0017'
  AND (SELECT count(*) = 17 FROM kovcheg_meta.schema_migrations),
  'the complete seventeen-migration Variant E chain must be recorded'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_personal_gate_families
    WHERE status IN ('active', 'suspended')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_personal_gate_sessions
    WHERE revoked_at IS NULL
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_email_challenges
    WHERE gate_session_id IS NOT NULL
      AND used_at IS NULL
      AND invalidated_at IS NULL
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_sessions AS application_session
    JOIN kovcheg.auth_email_challenges AS challenge
      ON challenge.id = application_session.source_challenge_id
    WHERE challenge.gate_session_id IS NOT NULL
      AND application_session.revoked_at IS NULL
  ),
  'all historical personal-gate authorization state must be terminal after upgrade'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_personal_gate_families
    WHERE id = '00000000-0000-4000-8000-000000006901'
      AND status <> 'revoked'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_personal_gate_sessions
    WHERE id = '00000000-0000-4000-8000-000000006902'
      AND revoked_at IS NULL
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_email_challenges
    WHERE id = '00000000-0000-4000-8000-000000006904'
      AND invalidated_at IS NULL
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_sessions
    WHERE id = '00000000-0000-4000-8000-000000006905'
      AND revoked_at IS NULL
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_passkey_credentials
    WHERE id = '00000000-0000-4000-8000-000000006906'
      AND revoked_at IS NOT NULL
  ),
  'the v15 fixture must retire gate-derived access without revoking its passkey'
);

SELECT pg_temp.assert_true(
  NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.auth_email_challenges',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.auth_sessions',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.auth_personal_gate_families',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.auth_personal_gate_sessions',
    'SELECT,INSERT,UPDATE,DELETE'
  ),
  'Variant E runtime must not receive direct auth or retired-gate DML'
);

SELECT pg_temp.assert_true(
  has_function_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.issue_auth_email_challenge(text,uuid,text,timestamp with time zone,timestamp with time zone,integer,interval,character varying)',
    'EXECUTE'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS procedure
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(
        procedure.proacl,
        pg_catalog.acldefault('f', procedure.proowner)
      )
    ) AS privilege
    WHERE procedure.oid =
      'kovcheg.issue_auth_email_challenge(text,uuid,text,timestamp with time zone,timestamp with time zone,integer,interval,character varying)'::regprocedure
      AND privilege.grantee = 0
      AND privilege.privilege_type = 'EXECUTE'
  )
  AND NOT has_function_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.issue_auth_challenge_for_active_account(text,uuid,text,timestamp with time zone,timestamp with time zone,integer,interval)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.admin_issue_auth_personal_gate(text,uuid,uuid,text,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.admin_reissue_auth_personal_gate(text,uuid,uuid,text,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.admin_revoke_auth_personal_gate(text,uuid,uuid,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.admin_resume_auth_personal_gate(text,uuid,uuid,timestamp with time zone,character varying)',
    'EXECUTE'
  ),
  'only the narrow Variant E issue surface may remain executable'
);

SELECT pg_temp.assert_true(
  (
    SELECT procedure.prosecdef
      AND procedure.proconfig = ARRAY['search_path=pg_catalog, kovcheg']
      AND owner.rolname = 'kovcheg_migration'
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
    WHERE procedure.oid =
      'kovcheg.issue_auth_email_challenge(text,uuid,text,timestamp with time zone,timestamp with time zone,integer,interval,character varying)'::regprocedure
  )
  AND (
    SELECT procedure.prosecdef
      AND procedure.proconfig = ARRAY['search_path=pg_catalog, kovcheg']
      AND owner.rolname = 'kovcheg_migration'
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
    WHERE procedure.oid =
      'kovcheg.reject_retired_gate_session_source()'::regprocedure
  )
  AND (
    SELECT procedure.prosecdef
      AND procedure.proconfig = ARRAY['search_path=pg_catalog, kovcheg']
      AND owner.rolname = 'kovcheg_migration'
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
    WHERE procedure.oid =
      'kovcheg.revoke_auth_access_on_account_deactivation()'::regprocedure
  ),
  'Variant E functions must be migration-owned security definers with fixed search paths'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 1
    FROM pg_catalog.pg_trigger AS trigger
    WHERE trigger.tgrelid = 'kovcheg.accounts'::regclass
      AND trigger.tgname = 'accounts_revoke_auth_access_on_deactivation'
      AND NOT trigger.tgisinternal
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_trigger AS trigger
    WHERE trigger.tgrelid = 'kovcheg.accounts'::regclass
      AND trigger.tgname = 'accounts_revoke_personal_gate_on_deactivation'
      AND NOT trigger.tgisinternal
  ),
  'the active account deactivation boundary must not be the retired gate trigger'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 1
      AND bool_and(event.outcome = 'success')
      AND bool_and(event.migration_version = '0017')
      AND bool_and(event.details = '{}'::jsonb)
    FROM kovcheg.audit_events AS event
    WHERE event.correlation_id = 'variant-email-normalized'
      AND event.action = 'auth.email-challenge.issued'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events AS event
    WHERE event.action = 'auth.email-challenge.issued'
      AND (
        NOT kovcheg.event_metadata_is_sanitized(event.details)
        OR event.details::text ~* '(email|otp|token|cookie|secret|code|verifier|contact|credential|public.?key)'
        OR event.details::text LIKE '%@%'
        OR event.details::text LIKE '%.invalid%'
        OR event.details::text ~ '[A-Za-z0-9_-]{43}'
      )
  ),
  'email challenge audit must be one sanitized event without contact or secret material'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 1
    FROM kovcheg.audit_events
    WHERE correlation_id = 'passkey-security-reset'
      AND action = 'auth.access.security-reset'
      AND migration_version = '0017'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events
    WHERE migration_version = '0017'
      AND action = 'auth.personal-gate.security-reset'
  ),
  'current security resets must use the generic Variant E audit action'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 1
      AND bool_and(gate_session_id IS NULL)
      AND bool_and(code_verifier = repeat('V', 43))
    FROM kovcheg.auth_email_challenges
    WHERE id = '00000000-0000-4000-8000-000000006101'
  )
  AND (
    SELECT count(*) = 1
      AND bool_and(source_challenge_id = '00000000-0000-4000-8000-000000006101')
    FROM kovcheg.auth_sessions
    WHERE id = '00000000-0000-4000-8000-000000006201'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_email_challenges
    WHERE id IN (
      '00000000-0000-4000-8000-000000006102',
      '00000000-0000-4000-8000-000000006103',
      '00000000-0000-4000-8000-000000006104',
      '00000000-0000-4000-8000-000000006199'
    )
  ),
  'neutral and invalid requests must leave no challenge or application-session state'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 1
      AND bool_and(gate_session_id IS NULL)
      AND bool_and(used_at IS NULL)
      AND bool_and(invalidated_at IS NULL)
    FROM kovcheg.auth_email_challenges
    WHERE account_id = '00000000-0000-4000-8000-000000006004'
  )
  AND (
    SELECT count(*) = 1
    FROM kovcheg.audit_events
    WHERE correlation_id LIKE 'variant-email-race-%'
      AND action = 'auth.email-challenge.issued'
  ),
  'concurrent issuance must commit one live challenge and one audit event'
);

BEGIN;

CREATE FUNCTION pg_temp.reject_variant_email_audit_fixture()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.action = 'auth.email-challenge.issued'
    AND NEW.correlation_id = 'variant-email-audit-rollback'
  THEN
    RAISE EXCEPTION 'synthetic Variant E audit failure';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER reject_variant_email_audit_fixture
BEFORE INSERT ON kovcheg.audit_events
FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_variant_email_audit_fixture();

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.issue_auth_email_challenge(
      'variant.user+tag@auth.invalid',
      '00000000-0000-4000-8000-000000006198',
      repeat('U', 43),
      '2030-01-01 01:30:00+00',
      '2030-01-01 01:40:00+00',
      5,
      interval '60 seconds',
      'variant-email-audit-rollback'
    );
    RAISE EXCEPTION 'a forced email challenge audit failure was accepted';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM = 'a forced email challenge audit failure was accepted' THEN
      RAISE;
    END IF;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_email_challenges
    WHERE id = '00000000-0000-4000-8000-000000006198'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events
    WHERE correlation_id = 'variant-email-audit-rollback'
  ),
  'audit failure must roll back challenge invalidation, insertion, and audit'
);

ROLLBACK;

BEGIN;

INSERT INTO kovcheg.auth_personal_gate_families (
  id,
  account_id,
  code_verifier,
  status,
  issued_at,
  revoked_at
) VALUES (
  '00000000-0000-4000-8000-000000006991',
  '00000000-0000-4000-8000-000000006004',
  repeat('Q', 43),
  'revoked',
  '2030-01-01 00:01:00+00',
  '2030-01-01 00:02:00+00'
);

INSERT INTO kovcheg.auth_personal_gate_sessions (
  id,
  family_id,
  account_id,
  token_verifier,
  client_idempotency_key,
  issued_at,
  expires_at,
  revoked_at
) VALUES (
  '00000000-0000-4000-8000-000000006992',
  '00000000-0000-4000-8000-000000006991',
  '00000000-0000-4000-8000-000000006004',
  repeat('R', 43),
  'retired-gate-source-fixture',
  '2030-01-01 00:02:00+00',
  '2030-01-08 00:02:00+00',
  '2030-01-01 00:03:00+00'
);

INSERT INTO kovcheg.auth_email_challenges (
  id,
  account_id,
  code_verifier,
  issued_at,
  expires_at,
  used_at,
  max_attempts,
  gate_session_id
) VALUES (
  '00000000-0000-4000-8000-000000006993',
  '00000000-0000-4000-8000-000000006004',
  repeat('S', 43),
  '2030-01-01 00:04:00+00',
  '2030-01-01 00:14:00+00',
  '2030-01-01 00:05:00+00',
  5,
  '00000000-0000-4000-8000-000000006992'
);

DO $$
BEGIN
  BEGIN
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
      '00000000-0000-4000-8000-000000006999',
      '00000000-0000-4000-8000-000000006004',
      repeat('L', 43),
      '2030-01-01 00:07:00+00',
      '2030-01-01 00:07:00+00',
      3600000,
      '2030-01-01 01:07:00+00',
      '2030-01-01 02:07:00+00',
      '00000000-0000-4000-8000-000000006993'
    );
    RAISE EXCEPTION 'a retired gate challenge created a new application session';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_sessions
    WHERE id = '00000000-0000-4000-8000-000000006999'
  ),
  'the retired gate source trigger must fail closed without a partial session'
);

ROLLBACK;

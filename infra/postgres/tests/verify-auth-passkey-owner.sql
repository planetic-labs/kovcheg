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
  kovcheg.current_migration_version() = '0016'
  AND (SELECT count(*) = 16 FROM kovcheg_meta.schema_migrations),
  'the complete sixteen-migration chain must be recorded'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_passkey_credentials
    WHERE id IN (
      '00000000-0000-4000-8000-000000005398',
      '00000000-0000-4000-8000-000000005399'
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events
    WHERE correlation_id IN (
      'passkey-register-unauthorized',
      'passkey-register-uv-denied',
      'passkey-login-uv-denied',
      'passkey-login-unknown'
    )
  ),
  'authorization and validation failures must leave no passkey state or audit'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 2
      AND bool_and(revoked_at = '2030-01-01 01:05:00+00'::timestamptz)
    FROM kovcheg.auth_passkey_credentials
    WHERE account_id = '00000000-0000-4000-8000-000000005001'
  )
  AND (
    SELECT count(*) = 3
      AND array_agg(sign_count_status ORDER BY occurred_at) = ARRAY[
        'not_advanced',
        'regressed',
        'advanced'
      ]::kovcheg.auth_passkey_sign_count_status[]
    FROM kovcheg.auth_passkey_assertion_evidence
    WHERE passkey_id = '00000000-0000-4000-8000-000000005301'
  )
  AND (
    SELECT count(*) = 1
      AND bool_and(sign_count_status = 'not_supported')
    FROM kovcheg.auth_passkey_assertion_evidence
    WHERE passkey_id = '00000000-0000-4000-8000-000000005302'
  )
  AND (
    SELECT count(*) = 4
      AND bool_and(source_challenge_id IS NULL)
      AND bool_and(revoked_at = '2030-01-01 01:05:00+00'::timestamptz)
    FROM kovcheg.auth_sessions
    WHERE id IN (
      '00000000-0000-4000-8000-000000005501',
      '00000000-0000-4000-8000-000000005502',
      '00000000-0000-4000-8000-000000005503',
      '00000000-0000-4000-8000-000000005504'
    )
  ),
  'counter risk evidence must be durable while passkey sessions bypass email challenges'
);

SELECT pg_temp.assert_true(
  (
    SELECT revoked_at = '2030-01-01 01:06:04+00'::timestamptz
    FROM kovcheg.auth_passkey_credentials
    WHERE id = '00000000-0000-4000-8000-000000005303'
  )
  AND (
    SELECT revoked_at = '2030-01-01 01:06:04+00'::timestamptz
    FROM kovcheg.auth_sessions
    WHERE id = '00000000-0000-4000-8000-000000005202'
  ),
  'deactivation must revoke passkeys and application sessions in one transaction'
);

SELECT pg_temp.assert_true(
  (
    SELECT sign_count = 11
      AND last_used_at = '2030-01-01 01:08:00+00'::timestamptz
    FROM kovcheg.auth_passkey_credentials
    WHERE id = '00000000-0000-4000-8000-000000005304'
  )
  AND (
    SELECT count(*) = 1
      AND bool_and(sign_count_status = 'advanced')
      AND bool_and(resulting_sign_count = 11)
    FROM kovcheg.auth_passkey_assertion_evidence
    WHERE id = '00000000-0000-4000-8000-000000005605'
  )
  AND (
    SELECT count(*) = 1
      AND bool_and(source_challenge_id IS NULL)
      AND bool_and(revoked_at IS NULL)
    FROM kovcheg.auth_sessions
    WHERE id = '00000000-0000-4000-8000-000000005505'
  )
  AND (
    SELECT count(*) = 1
    FROM kovcheg.audit_events
    WHERE correlation_id = 'passkey-race-login'
  ),
  'concurrent identical assertions must commit one session, evidence row, and audit event'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT expected.correlation_id
    FROM (
      VALUES
        ('passkey-register-primary', 1),
        ('passkey-register-secondary', 1),
        ('passkey-login-not-advanced', 1),
        ('passkey-login-regressed', 1),
        ('passkey-login-advanced', 1),
        ('passkey-login-not-supported', 1),
        ('passkey-security-reset', 1),
        ('passkey-deactivation-register', 1),
        ('passkey-race-register', 1),
        ('passkey-race-login', 1)
    ) AS expected(correlation_id, event_count)
    WHERE (
      SELECT count(*)
      FROM kovcheg.audit_events AS event
      WHERE event.correlation_id = expected.correlation_id
    ) <> expected.event_count
  ),
  'each protected passkey mutation must append exactly one audit event'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events AS event
    WHERE event.correlation_id LIKE 'passkey-%'
      AND event.action IN (
        'auth.passkey.registered',
        'auth.passkey.authenticated',
        'auth.access.security-reset'
      )
      AND (
        event.outcome <> 'success'
        OR event.migration_version <> '0016'
        OR NOT kovcheg.event_metadata_is_sanitized(event.details)
        OR event.details::text ~* '(email|otp|token|cookie|secret|code|verifier|contact|credential|public.?key)'
        OR event.details::text LIKE '%@%'
        OR event.details::text LIKE '%.invalid%'
        OR event.details::text ~ '[A-Za-z0-9_-]{43}'
      )
  ),
  'passkey audit details must contain only sanitized states and counters'
);

SELECT pg_temp.assert_true(
  NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.auth_passkey_credentials',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.auth_passkey_assertion_evidence',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_function_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.auth_passkey_audit(character varying,uuid,character varying,uuid,jsonb)',
    'EXECUTE'
  )
  AND NOT pg_has_role('kovcheg_auth_app', 'kovcheg_migration', 'member')
  AND NOT pg_has_role('kovcheg_auth_app', 'kovcheg_runtime', 'member')
  AND NOT pg_has_role('kovcheg_auth_app', 'kovcheg_audit', 'member')
  AND (
    SELECT NOT rolsuper
      AND NOT rolcreatedb
      AND NOT rolcreaterole
      AND NOT rolbypassrls
    FROM pg_catalog.pg_roles
    WHERE rolname = 'kovcheg_auth_app'
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
    WHERE procedure.oid IN (
        'kovcheg.register_auth_passkey(text,uuid,bytea,bytea,bigint,kovcheg.auth_passkey_transport[],uuid,text,boolean,boolean,boolean,timestamp with time zone,character varying)'::regprocedure,
        'kovcheg.read_auth_passkey_by_credential_id(bytea,timestamp with time zone)'::regprocedure,
        'kovcheg.complete_auth_passkey_login(bytea,bigint,bigint,boolean,boolean,boolean,uuid,uuid,text,bigint,timestamp with time zone,timestamp with time zone,character varying)'::regprocedure
      )
      AND privilege.grantee = 0
      AND privilege.privilege_type = 'EXECUTE'
  ),
  'passkey state, ownership, audit, and public execute must preserve least privilege'
);

BEGIN;

CREATE FUNCTION pg_temp.reject_passkey_audit_fixture()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.action = 'auth.passkey.registered'
    AND NEW.correlation_id = 'passkey-register-audit-rollback'
  THEN
    RAISE EXCEPTION 'synthetic passkey audit failure';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER reject_passkey_audit_fixture
BEFORE INSERT ON kovcheg.audit_events
FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_passkey_audit_fixture();

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.register_auth_passkey(
      repeat('J', 42) || '5',
      '00000000-0000-4000-8000-000000005397',
      decode(repeat('97', 32), 'hex'),
      decode(repeat('a7', 64), 'hex'),
      1,
      ARRAY['internal']::kovcheg.auth_passkey_transport[],
      '00000000-0000-4000-8000-000000005497',
      'packed',
      false,
      false,
      true,
      '2030-01-01 01:09:00+00',
      'passkey-register-audit-rollback'
    );
    RAISE EXCEPTION 'a forced passkey audit failure was accepted';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM = 'a forced passkey audit failure was accepted' THEN
      RAISE;
    END IF;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_passkey_credentials
    WHERE id = '00000000-0000-4000-8000-000000005397'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events
    WHERE correlation_id = 'passkey-register-audit-rollback'
  ),
  'audit failure must roll back the protected passkey mutation and audit'
);

ROLLBACK;

DO $$
BEGIN
  BEGIN
    UPDATE kovcheg.auth_passkey_assertion_evidence
    SET observed_sign_count = observed_sign_count;
    RAISE EXCEPTION 'append-only passkey evidence was mutable';
  EXCEPTION WHEN object_not_in_prerequisite_state THEN
    NULL;
  END;
END;
$$;

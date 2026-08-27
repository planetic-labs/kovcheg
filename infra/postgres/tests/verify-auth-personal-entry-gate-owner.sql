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
  kovcheg.current_migration_version() = '0014'
  AND (SELECT count(*) = 14 FROM kovcheg_meta.schema_migrations),
  'the complete fourteen-migration chain must be recorded'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_personal_gate_families
    WHERE id IN (
      '00000000-0000-4000-8000-000000004098',
      '00000000-0000-4000-8000-000000004099'
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events
    WHERE correlation_id = 'gate-unauthorized-issue'
  ),
  'authorization and audit failures must roll back personal gate mutations and audit'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 2
      AND bool_and(status = 'revoked')
    FROM kovcheg.auth_personal_gate_families
    WHERE account_id = '00000000-0000-4000-8000-000000004001'
  )
  AND (
    SELECT count(*) = 3
      AND bool_and(revoked_at IS NOT NULL)
    FROM kovcheg.auth_personal_gate_sessions
    WHERE account_id = '00000000-0000-4000-8000-000000004001'
  ),
  'reissue, revocation, and security reset must preserve one auditable lifecycle'
);

SELECT pg_temp.assert_true(
  (
    SELECT status = 'active'
      AND mismatch_count = 0
      AND pause_count = 0
    FROM kovcheg.auth_personal_gate_families
    WHERE id = '00000000-0000-4000-8000-000000004110'
  )
  AND (
    SELECT count(*) = 1
      AND bool_and(revoked_at IS NULL)
    FROM kovcheg.auth_personal_gate_sessions
    WHERE family_id = '00000000-0000-4000-8000-000000004110'
      AND client_idempotency_key = 'synthetic-client-race-001'
  ),
  'concurrent activation must preserve one current family and one live client session'
);

SELECT pg_temp.assert_true(
  (
    SELECT status = 'revoked'
      AND revoked_at = '2030-01-01 00:57:05+00'::timestamptz
    FROM kovcheg.auth_personal_gate_families
    WHERE id = '00000000-0000-4000-8000-000000004120'
  )
  AND (
    SELECT revoked_at = '2030-01-01 00:57:05+00'::timestamptz
    FROM kovcheg.auth_personal_gate_sessions
    WHERE id = '00000000-0000-4000-8000-000000004220'
  )
  AND (
    SELECT revoked_at = '2030-01-01 00:57:05+00'::timestamptz
      AND source_challenge_id = '00000000-0000-4000-8000-000000004320'
    FROM kovcheg.auth_sessions
    WHERE id = '00000000-0000-4000-8000-000000004420'
  ),
  'account deactivation must atomically bind and revoke every derived auth record'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT expected.correlation_id
    FROM (
      VALUES
        ('gate-issue-001', 1),
        ('gate-activate-001', 1),
        ('gate-mismatch-pause-1', 1),
        ('gate-mismatch-pause-2', 1),
        ('gate-mismatch-pause-3', 1),
        ('gate-resume-001', 1),
        ('gate-activate-002', 1),
        ('gate-reissue-001', 1),
        ('gate-activate-003', 1),
        ('gate-revoke-001', 1),
        ('gate-security-reset-001', 1),
        ('gate-race-activate', 1),
        ('gate-deactivation-issue', 1),
        ('gate-deactivation-activate', 1)
    ) AS expected(correlation_id, event_count)
    WHERE (
      SELECT count(*)
      FROM kovcheg.audit_events AS event
      WHERE event.correlation_id = expected.correlation_id
    ) <> expected.event_count
  ),
  'each protected personal gate mutation must append exactly one audit event'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events AS event
    WHERE event.correlation_id LIKE 'gate-%'
      AND (
        event.outcome <> 'success'
        OR event.migration_version <> '0014'
        OR NOT kovcheg.event_metadata_is_sanitized(event.details)
        OR event.details::text ~* '(email|otp|token|cookie|secret|code|verifier|contact)'
        OR event.details::text LIKE '%@%'
        OR event.details::text LIKE '%.invalid%'
        OR event.details::text ~ '[A-Za-z0-9_-]{43}'
      )
  ),
  'personal gate audit must contain only sanitized identifiers, state, and counters'
);

SELECT pg_temp.assert_true(
  NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.auth_personal_gate_families',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.auth_personal_gate_sessions',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_function_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.auth_personal_gate_audit(character varying,uuid,character varying,character varying,uuid,jsonb)',
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
    WHERE procedure.oid = 'kovcheg.activate_auth_personal_gate(text,uuid,text,text,timestamp with time zone,character varying)'::regprocedure
      AND privilege.grantee = 0
      AND privilege.privilege_type = 'EXECUTE'
  ),
  'personal gate state and internal audit helpers must preserve least privilege'
);

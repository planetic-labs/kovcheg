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
  current_setting('password_encryption') = 'scram-sha-256',
  'password_encryption must use SCRAM'
);
SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_hba_file_rules
    WHERE error IS NOT NULL OR auth_method = 'trust'
  ),
  'pg_hba.conf must be valid and contain no trust rule'
);
SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_hba_file_rules
    WHERE type LIKE 'host%' AND auth_method <> 'scram-sha-256'
  ),
  'every host rule must use SCRAM'
);
SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 6
    FROM pg_catalog.pg_roles
    WHERE rolname IN (
      'kovcheg_migration',
      'kovcheg_runtime',
      'kovcheg_audit',
      'kovcheg_migrator',
      'kovcheg_app',
      'kovcheg_audit_writer'
    )
  ),
  'all migration, runtime, and audit roles must exist'
);
SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname LIKE 'kovcheg_%'
      AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
  ),
  'application roles must not have administrative attributes'
);
SELECT pg_temp.assert_true(
  (
    SELECT bool_and(rolpassword LIKE 'SCRAM-SHA-256$%')
    FROM pg_catalog.pg_authid
    WHERE rolname IN ('kovcheg_migrator', 'kovcheg_app', 'kovcheg_audit_writer')
  ),
  'every login role password must be stored as a SCRAM verifier'
);
SELECT pg_temp.assert_true(
  pg_has_role('kovcheg_migrator', 'kovcheg_migration', 'MEMBER')
  AND pg_has_role('kovcheg_app', 'kovcheg_runtime', 'MEMBER')
  AND pg_has_role('kovcheg_audit_writer', 'kovcheg_audit', 'MEMBER')
  AND NOT pg_has_role('kovcheg_migrator', 'kovcheg_runtime', 'MEMBER')
  AND NOT pg_has_role('kovcheg_migrator', 'kovcheg_audit', 'MEMBER')
  AND NOT pg_has_role('kovcheg_app', 'kovcheg_migration', 'MEMBER')
  AND NOT pg_has_role('kovcheg_app', 'kovcheg_audit', 'MEMBER')
  AND NOT pg_has_role('kovcheg_audit_writer', 'kovcheg_migration', 'MEMBER')
  AND NOT pg_has_role('kovcheg_audit_writer', 'kovcheg_runtime', 'MEMBER'),
  'login roles must inherit only their explicit group role'
);
SELECT pg_temp.assert_true(
  NOT has_table_privilege('kovcheg_app', 'kovcheg.audit_events', 'SELECT,INSERT,UPDATE,DELETE')
  AND NOT has_table_privilege(
    'kovcheg_audit_writer',
    'kovcheg.audit_events',
    'SELECT,INSERT,UPDATE,DELETE'
  ),
  'audit tables must not expose direct DML to runtime or audit logins'
);
SELECT pg_temp.assert_true(
  has_function_privilege(
    'kovcheg_audit_writer',
    'kovcheg.append_audit_event(character varying,character varying,uuid,character varying,character varying,uuid,kovcheg.event_outcome,jsonb)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    'kovcheg_app',
    'kovcheg.append_audit_event(character varying,character varying,uuid,character varying,character varying,uuid,kovcheg.event_outcome,jsonb)',
    'EXECUTE'
  ),
  'only the audit role may append through the protected audit function'
);

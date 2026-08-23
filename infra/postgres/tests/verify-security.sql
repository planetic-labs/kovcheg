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
    SELECT count(*) = 8
    FROM pg_catalog.pg_roles
    WHERE rolname IN (
      'kovcheg_migration',
      'kovcheg_runtime',
      'kovcheg_audit',
      'kovcheg_migrator',
      'kovcheg_app',
      'kovcheg_audit_writer',
      'kovcheg_auth_runtime',
      'kovcheg_auth_app'
    )
  ),
  'all migration, runtime, audit, and auth roles must exist'
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
    WHERE rolname IN (
      'kovcheg_migrator',
      'kovcheg_app',
      'kovcheg_audit_writer',
      'kovcheg_auth_app'
    )
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
  pg_has_role('kovcheg_auth_app', 'kovcheg_auth_runtime', 'MEMBER')
  AND NOT pg_has_role('kovcheg_auth_app', 'kovcheg_migration', 'MEMBER')
  AND NOT pg_has_role('kovcheg_auth_app', 'kovcheg_runtime', 'MEMBER')
  AND NOT pg_has_role('kovcheg_auth_app', 'kovcheg_audit', 'MEMBER')
  AND NOT pg_has_role('kovcheg_app', 'kovcheg_auth_runtime', 'MEMBER')
  AND NOT pg_has_role('kovcheg_audit_writer', 'kovcheg_auth_runtime', 'MEMBER')
  AND NOT pg_has_role('kovcheg_migrator', 'kovcheg_auth_runtime', 'MEMBER'),
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

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'kovcheg'
      AND procedure.proname = 'admin_create_auth_account'
  ) THEN
    PERFORM pg_temp.assert_true(
      has_function_privilege(
        'kovcheg_auth_app',
        'kovcheg.admin_create_auth_account(text,uuid,text,text,timestamp with time zone,character varying)',
        'EXECUTE'
      )
      AND has_function_privilege(
        'kovcheg_auth_app',
        'kovcheg.admin_update_auth_account(text,uuid,text,text,timestamp with time zone,character varying)',
        'EXECUTE'
      )
      AND has_function_privilege(
        'kovcheg_auth_app',
        'kovcheg.admin_set_auth_account_status(text,uuid,kovcheg.account_status,timestamp with time zone,character varying)',
        'EXECUTE'
      )
      AND has_function_privilege(
        'kovcheg_auth_app',
        'kovcheg.admin_revoke_auth_session(text,uuid,uuid,timestamp with time zone,character varying)',
        'EXECUTE'
      )
      AND has_function_privilege(
        'kovcheg_auth_app',
        'kovcheg.admin_revoke_all_auth_sessions(text,uuid,timestamp with time zone,character varying)',
        'EXECUTE'
      ),
      'the auth login must execute each protected administrative operation'
    );

    PERFORM pg_temp.assert_true(
      NOT has_function_privilege(
        'kovcheg_auth_app',
        'kovcheg.require_active_auth_administrator(text,timestamp with time zone)',
        'EXECUTE'
      )
      AND NOT has_function_privilege(
        'kovcheg_auth_app',
        'kovcheg.create_auth_account(uuid,text,text)',
        'EXECUTE'
      )
      AND NOT has_function_privilege(
        'kovcheg_auth_app',
        'kovcheg.set_auth_account_status_and_revoke(uuid,kovcheg.account_status,timestamp with time zone)',
        'EXECUTE'
      )
      AND NOT has_function_privilege(
        'kovcheg_auth_app',
        'kovcheg.revoke_auth_session_by_id(uuid,timestamp with time zone)',
        'EXECUTE'
      )
      AND NOT has_function_privilege(
        'kovcheg_auth_app',
        'kovcheg.append_audit_event(character varying,character varying,uuid,character varying,character varying,uuid,kovcheg.event_outcome,jsonb)',
        'EXECUTE'
      ),
      'the auth login must not execute bypass or general audit functions'
    );
  END IF;
END;
$$;

DO $$
BEGIN
  IF to_regprocedure(
    'kovcheg.validate_auth_session(text,timestamp with time zone)'
  ) IS NOT NULL THEN
    PERFORM pg_temp.assert_true(
      has_function_privilege(
        'kovcheg_auth_app',
        'kovcheg.validate_auth_session(text,timestamp with time zone)',
        'EXECUTE'
      )
      AND NOT has_function_privilege(
        'kovcheg_app',
        'kovcheg.validate_auth_session(text,timestamp with time zone)',
        'EXECUTE'
      )
      AND NOT has_function_privilege(
        'kovcheg_audit_writer',
        'kovcheg.validate_auth_session(text,timestamp with time zone)',
        'EXECUTE'
      ),
      'only the auth login may execute non-touch session validation'
    );
  END IF;
END;
$$;

DO $$
DECLARE
  expected_event_count integer;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM kovcheg.accounts
    WHERE id = '00000000-0000-4000-8000-000000003005'
  ) THEN
    SELECT count(*)
    INTO expected_event_count
    FROM kovcheg.audit_events AS event
    WHERE event.correlation_id IN (
      'auth-admin-create-001',
      'auth-admin-update-001',
      'auth-admin-create-secondary',
      'auth-admin-revoke-one-001',
      'auth-admin-revoke-one-retry',
      'auth-admin-status-deactivated',
      'auth-admin-status-active',
      'auth-admin-revoke-cross-owner',
      'auth-admin-status-deactivate-actor',
      'auth-admin-create-race-target'
    )
    OR event.correlation_id LIKE 'auth-admin-revoke-all-race-%';

    PERFORM pg_temp.assert_true(
      expected_event_count = 22,
      'every successful administrative call must append exactly one audit event'
    );

    PERFORM pg_temp.assert_true(
      NOT EXISTS (
        SELECT 1
        FROM (
          VALUES
            ('auth-admin-create-001'),
            ('auth-admin-update-001'),
            ('auth-admin-create-secondary'),
            ('auth-admin-revoke-one-001'),
            ('auth-admin-revoke-one-retry'),
            ('auth-admin-status-deactivated'),
            ('auth-admin-status-active'),
            ('auth-admin-revoke-cross-owner'),
            ('auth-admin-status-deactivate-actor'),
            ('auth-admin-create-race-target')
        ) AS expected(correlation_id)
        WHERE (
          SELECT count(*)
          FROM kovcheg.audit_events AS event
          WHERE event.correlation_id = expected.correlation_id
        ) <> 1
      )
      AND NOT EXISTS (
        SELECT 1
        FROM generate_series(1, 12) AS race(race_number)
        WHERE (
          SELECT count(*)
          FROM kovcheg.audit_events AS event
          WHERE event.correlation_id =
            'auth-admin-revoke-all-race-' || race.race_number::text
        ) <> 1
      ),
      'each administrative correlation ID must identify one and only one audit event'
    );

    PERFORM pg_temp.assert_true(
      NOT EXISTS (
        SELECT 1
        FROM kovcheg.audit_events AS event
        WHERE event.correlation_id LIKE 'auth-admin-failed-%'
      ),
      'authorization failures and rolled-back mutations must append no audit event'
    );

    PERFORM pg_temp.assert_true(
      NOT EXISTS (
        SELECT 1
        FROM kovcheg.audit_events AS event
        CROSS JOIN LATERAL pg_catalog.jsonb_object_keys(event.details) AS detail(key)
        WHERE event.correlation_id LIKE 'auth-admin-%'
          AND detail.key NOT IN (
            'authRole',
            'accountStatus',
            'starterChatCount',
            'invalidatedChallengeCount',
            'revokedSessionCount'
          )
      )
      AND NOT EXISTS (
        SELECT 1
        FROM kovcheg.audit_events AS event
        WHERE event.correlation_id LIKE 'auth-admin-%'
          AND (
            event.details::text LIKE '%@%'
            OR event.details::text LIKE '%.invalid%'
            OR event.details::text ~ '[A-Za-z0-9_-]{43}'
          )
      ),
      'administrative audit details must contain only the sanitized allowlisted fields'
    );

    PERFORM pg_temp.assert_true(
      NOT EXISTS (
        SELECT 1
        FROM kovcheg.audit_events AS event
        WHERE event.correlation_id LIKE 'auth-admin-%'
          AND (
            event.actor_account_id <> '00000000-0000-4000-8000-000000003001'
            OR event.outcome <> 'success'
            OR event.migration_version <> kovcheg.current_migration_version()
          )
      ),
      'administrative audit events must record the verified actor and current migration'
    );
  END IF;
END;
$$;

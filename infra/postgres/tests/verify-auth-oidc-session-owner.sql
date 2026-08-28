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
  'the complete seventeen-migration OIDC application-session chain must be recorded'
);

SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'kovcheg'
      AND table_name = 'auth_sessions'
      AND column_name = 'source_oidc_token_verifier'
      AND character_maximum_length = 43
      AND is_nullable = 'YES'
  )
  AND EXISTS (
    SELECT 1
    FROM pg_catalog.pg_constraint
    WHERE conrelid = 'kovcheg.auth_sessions'::regclass
      AND conname = 'auth_sessions_source_oidc_token_verifier_check'
      AND convalidated
  )
  AND EXISTS (
    SELECT 1
    FROM pg_catalog.pg_constraint
    WHERE conrelid = 'kovcheg.auth_sessions'::regclass
      AND conname = 'auth_sessions_source_oidc_token_verifier_unique'
      AND contype = 'u'
  ),
  'OIDC source evidence must be bounded, one-way, optional for historical sessions, and unique'
);

SELECT pg_temp.assert_true(
  has_function_privilege(
    'kovcheg_auth_runtime',
    'kovcheg.create_oidc_application_session(uuid,text,uuid,text,timestamp with time zone,bigint,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS procedure
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
    ) AS privilege
    WHERE procedure.oid =
      'kovcheg.create_oidc_application_session(uuid,text,uuid,text,timestamp with time zone,bigint,timestamp with time zone,character varying)'::regprocedure
      AND privilege.grantee = 0
      AND privilege.privilege_type = 'EXECUTE'
  )
  AND (
    SELECT procedure.prosecdef
      AND procedure.proconfig = ARRAY['search_path=pg_catalog, kovcheg']
      AND owner.rolname = 'kovcheg_migration'
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
    WHERE procedure.oid =
      'kovcheg.create_oidc_application_session(uuid,text,uuid,text,timestamp with time zone,bigint,timestamp with time zone,character varying)'::regprocedure
  ),
  'only the auth runtime may execute the migration-owned fixed-search-path bridge'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 1
      AND bool_and(event.migration_version = '0017')
      AND bool_and(event.actor_account_id = '00000000-0000-4000-8000-000000003002')
      AND bool_and(event.target_type = 'auth_session')
      AND bool_and(event.outcome = 'success')
      AND bool_and(event.details = '{}'::jsonb)
    FROM kovcheg.audit_events AS event
    WHERE event.correlation_id = 'oidc-session-active-account'
      AND event.action = 'auth.oidc.application-session.created'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events AS event
    WHERE event.action = 'auth.oidc.application-session.created'
      AND (
        NOT kovcheg.event_metadata_is_sanitized(event.details)
        OR event.details::text ~* '(token|cookie|secret|verifier|email|credential)'
        OR event.details::text ~ '[A-Za-z0-9_-]{43}'
      )
  ),
  'the OIDC session audit must contain only sanitized technical evidence'
);

SELECT pg_temp.assert_true(
  (SELECT count(*) = 1 FROM kovcheg.auth_sessions WHERE source_oidc_token_verifier = repeat('q', 43))
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_sessions
    WHERE id IN (
      '00000000-0000-4000-8000-000000003291',
      '00000000-0000-4000-8000-000000003292'
    )
  ),
  'the bridge must persist one active-account session and no replay or unknown-account session'
);

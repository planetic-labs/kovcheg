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
  kovcheg.current_migration_version() = '0004'
  AND (SELECT count(*) = 4 FROM kovcheg_meta.schema_migrations),
  'the A4 message-flow boundary must remain independently upgradeable'
);
SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.create_text_message(uuid,uuid,character varying,character varying,text,character varying)'
  ) IS NOT NULL,
  'the A4 message-flow entrypoint must exist at migration v4'
);
SELECT pg_temp.assert_true(
  to_regclass('kovcheg.account_auth_profiles') IS NULL
  AND to_regclass('kovcheg.auth_email_challenges') IS NULL
  AND to_regclass('kovcheg.auth_sessions') IS NULL
  AND to_regclass('kovcheg.oidc_clients') IS NULL
  AND to_regclass('kovcheg.oidc_provider_artifacts') IS NULL,
  'auth persistence must not exist before migration v5'
);
SELECT pg_temp.assert_true(
  has_function_privilege(
    'kovcheg_app',
    'kovcheg.create_text_message(uuid,uuid,character varying,character varying,text,character varying)',
    'EXECUTE'
  ),
  'the A4 runtime grant must remain available at migration v4'
);

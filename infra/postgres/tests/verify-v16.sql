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
  'the sixteen-migration Variant E boundary must remain complete'
);

SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.issue_auth_email_challenge(text,uuid,text,timestamp with time zone,timestamp with time zone,integer,interval,character varying)'
  ) IS NOT NULL
  AND to_regprocedure(
    'kovcheg.create_oidc_application_session(uuid,text,uuid,text,timestamp with time zone,bigint,timestamp with time zone,character varying)'
  ) IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'kovcheg'
      AND table_name = 'auth_sessions'
      AND column_name = 'source_oidc_token_verifier'
  ),
  'the v16 boundary must remain independently upgradeable before the OIDC session bridge'
);

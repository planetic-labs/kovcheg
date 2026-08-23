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
  kovcheg.current_migration_version() = '0006'
  AND (SELECT count(*) = 6 FROM kovcheg_meta.schema_migrations),
  'the six-migration auth administration boundary must be recorded'
);

SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.admin_create_auth_account(text,uuid,text,text,timestamp with time zone,character varying)'
  ) IS NOT NULL
  AND to_regprocedure(
    'kovcheg.admin_update_auth_account(text,uuid,text,text,timestamp with time zone,character varying)'
  ) IS NOT NULL
  AND to_regprocedure(
    'kovcheg.admin_set_auth_account_status(text,uuid,kovcheg.account_status,timestamp with time zone,character varying)'
  ) IS NOT NULL
  AND to_regprocedure(
    'kovcheg.admin_revoke_auth_session(text,uuid,uuid,timestamp with time zone,character varying)'
  ) IS NOT NULL
  AND to_regprocedure(
    'kovcheg.admin_revoke_all_auth_sessions(text,uuid,timestamp with time zone,character varying)'
  ) IS NOT NULL,
  'the protected auth administration boundary must remain complete at migration v6'
);

SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.validate_auth_session(text,timestamp with time zone)'
  ) IS NULL,
  'non-touch session validation must not exist before migration v7'
);

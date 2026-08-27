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
  'the fourteen-migration personal-entry boundary must remain complete'
);

SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.admin_security_reset_auth_access(text,uuid,timestamp with time zone,character varying)'
  ) IS NOT NULL
  AND to_regprocedure(
    'kovcheg.activate_auth_personal_gate(text,uuid,text,text,timestamp with time zone,character varying)'
  ) IS NOT NULL,
  'the v14 personal-entry boundary must remain upgradeable'
);

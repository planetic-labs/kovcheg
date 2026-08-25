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
  kovcheg.current_migration_version() = '0012'
  AND (SELECT count(*) = 12 FROM kovcheg_meta.schema_migrations),
  'the twelve-migration server role-capability boundary must remain complete'
);

SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.read_current_principal_authorization(text,timestamp with time zone,boolean)'
  ) IS NOT NULL
  AND to_regprocedure(
    'kovcheg.admin_grant_functional_grant(text,uuid,kovcheg.platform_role,character varying,bigint,timestamp with time zone,character varying)'
  ) IS NOT NULL,
  'the v12 principal readback and functional-grant boundary must remain upgradeable'
);

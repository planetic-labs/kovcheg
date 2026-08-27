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
  kovcheg.current_migration_version() = '0013'
  AND (SELECT count(*) = 13 FROM kovcheg_meta.schema_migrations),
  'the thirteen-migration role-administration boundary must remain complete'
);

SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.mutate_functional_grant(text,uuid,kovcheg.platform_role,boolean,character varying,bigint,timestamp with time zone,character varying)'
  ) IS NOT NULL,
  'the v13 role-administration capability boundary must remain upgradeable'
);

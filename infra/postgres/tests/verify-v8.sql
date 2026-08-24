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
  kovcheg.current_migration_version() = '0008'
  AND (SELECT count(*) = 8 FROM kovcheg_meta.schema_migrations),
  'the eight-migration persona data-owner boundary must be recorded'
);

SELECT pg_temp.assert_true(
  to_regclass('kovcheg.system_persona_operator_grants') IS NOT NULL
  AND to_regprocedure(
    'kovcheg.admin_grant_system_persona_operator(text,uuid,uuid,timestamp with time zone,character varying)'
  ) IS NOT NULL
  AND to_regprocedure(
    'kovcheg.admin_revoke_system_persona_operator(text,uuid,uuid,timestamp with time zone,character varying)'
  ) IS NOT NULL,
  'the persona data-owner boundary must remain complete at migration v8'
);

SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.authorize_system_persona_action(uuid,uuid,uuid,timestamp with time zone)'
  ) IS NULL,
  'runtime persona authorization must not exist before migration v9'
);

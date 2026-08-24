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
  kovcheg.current_migration_version() = '0007'
  AND (SELECT count(*) = 7 FROM kovcheg_meta.schema_migrations),
  'the seven-migration non-touch session boundary must be recorded'
);

SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.validate_auth_session(text,timestamp with time zone)'
  ) IS NOT NULL,
  'non-touch session validation must remain available at migration v7'
);

SELECT pg_temp.assert_true(
  to_regclass('kovcheg.system_persona_operator_grants') IS NULL
  AND to_regprocedure(
    'kovcheg.admin_grant_system_persona_operator(text,uuid,uuid,timestamp with time zone,character varying)'
  ) IS NULL
  AND to_regprocedure(
    'kovcheg.admin_revoke_system_persona_operator(text,uuid,uuid,timestamp with time zone,character varying)'
  ) IS NULL,
  'persona operator grants must not exist before migration v8'
);

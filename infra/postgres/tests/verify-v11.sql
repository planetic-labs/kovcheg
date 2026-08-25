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
  kovcheg.current_migration_version() = '0011'
  AND (SELECT count(*) = 11 FROM kovcheg_meta.schema_migrations),
  'the eleven-migration persona privacy-race boundary must remain complete'
);

SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.authorize_system_persona_action(uuid,uuid,uuid,timestamp with time zone)'
  ) IS NOT NULL
  AND to_regprocedure(
    'kovcheg.create_text_message_for_session(uuid,uuid,uuid,uuid,character varying,character varying,text,character varying,timestamp with time zone)'
  ) IS NOT NULL,
  'the locked persona authorization and session-bound message entrypoint must remain available at migration v11'
);

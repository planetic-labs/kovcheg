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
  kovcheg.current_migration_version() = '0009'
  AND (SELECT count(*) = 9 FROM kovcheg_meta.schema_migrations),
  'the nine-migration persona authorization boundary must remain complete'
);

SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.create_text_message_for_session(uuid,uuid,uuid,uuid,character varying,character varying,text,character varying,timestamp with time zone)'
  ) IS NULL,
  'the persona message-audit entrypoint must not exist before migration v10'
);

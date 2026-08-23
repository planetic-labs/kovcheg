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
  kovcheg.current_migration_version() = '0003'
  AND (SELECT count(*) = 3 FROM kovcheg_meta.schema_migrations),
  'the v3 foundation-review boundary must remain independently upgradeable'
);
SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.create_text_message(uuid,uuid,character varying,character varying,text,character varying)'
  ) IS NULL,
  'the A4 message-flow entrypoint must not exist before migration v4'
);
SELECT pg_temp.assert_true(
  to_regclass('kovcheg.account_auth_profiles') IS NULL
  AND to_regclass('kovcheg.auth_email_challenges') IS NULL
  AND to_regclass('kovcheg.auth_sessions') IS NULL,
  'the v3 boundary must remain valid before additive auth persistence'
);
SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM kovcheg.messages
    WHERE sender_account_id = '00000000-0000-4000-8000-000000002001'
  )
  AND EXISTS (
    SELECT 1 FROM kovcheg.outbox_events
    WHERE idempotency_key = 'outbox-message-001'
  ),
  'pre-v3 message and outbox data must remain readable at the v3 boundary'
);

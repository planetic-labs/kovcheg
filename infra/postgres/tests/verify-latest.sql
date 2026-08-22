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
  kovcheg.current_migration_version() = '0002',
  'the latest compatible migration must be recorded'
);
SELECT pg_temp.assert_true(
  (SELECT count(*) = 2 FROM kovcheg_meta.schema_migrations),
  'exactly two checksummed migrations must be applied'
);
SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 2
    FROM information_schema.columns
    WHERE table_schema = 'kovcheg'
      AND table_name = 'outbox_events'
      AND column_name IN ('claim_token', 'claim_expires_at')
  ),
  'N to N+1 must add nullable outbox claim metadata'
);
SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid = 'kovcheg.outbox_events'::regclass
      AND conname = 'outbox_events_claim_shape_check'
      AND convalidated
  ),
  'the additive outbox claim constraint must be validated'
);
SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM pg_catalog.pg_indexes
    WHERE schemaname = 'kovcheg' AND indexname = 'outbox_events_expired_claim_idx'
  ),
  'the N+1 query-plan index must exist'
);
SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM kovcheg.messages
    WHERE sender_account_id = '00000000-0000-4000-8000-000000002001'
  )
  AND EXISTS (
    SELECT 1 FROM kovcheg.outbox_events
    WHERE idempotency_key = 'outbox-message-001' AND claim_token IS NULL
  ),
  'N data must remain readable after N+1'
);

INSERT INTO kovcheg.outbox_events (
  aggregate_type,
  aggregate_id,
  event_name,
  idempotency_key,
  correlation_id,
  migration_version,
  payload
) VALUES (
  'database',
  '00000000-0000-4000-8000-000000002001',
  'database.compatibility-check',
  'outbox-compatible-old-shape',
  'database-compatibility-001',
  '0002',
  '{"fixture":"synthetic"}'::jsonb
);

SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM kovcheg.outbox_events
    WHERE idempotency_key = 'outbox-compatible-old-shape'
      AND claim_token IS NULL
      AND claim_expires_at IS NULL
  ),
  'the pre-N+1 insert shape must remain compatible'
);

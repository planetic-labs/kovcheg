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
  'database.runtime-claim-check',
  'runtime-claim-' || kovcheg.current_migration_version(),
  'database-runtime-claim-' || kovcheg.current_migration_version(),
  kovcheg.current_migration_version(),
  '{"fixture":"synthetic"}'::jsonb
);

WITH candidate AS (
  SELECT id
  FROM kovcheg.outbox_events
  WHERE idempotency_key = 'runtime-claim-' || kovcheg.current_migration_version()
    AND delivered_at IS NULL
    AND available_at <= clock_timestamp()
    AND (claim_token IS NULL OR claim_expires_at <= clock_timestamp())
  FOR UPDATE SKIP LOCKED
)
UPDATE kovcheg.outbox_events AS event
SET claim_token = gen_random_uuid(),
    claim_expires_at = clock_timestamp() + interval '5 minutes',
    attempt_count = attempt_count + 1
FROM candidate
WHERE event.id = candidate.id;

SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1
    FROM kovcheg.outbox_events
    WHERE idempotency_key = 'runtime-claim-' || kovcheg.current_migration_version()
      AND claim_token IS NOT NULL
      AND claim_expires_at IS NOT NULL
      AND attempt_count = 1
      AND delivered_at IS NULL
  ),
  'runtime must be able to claim one pending outbox event'
);

DO $$
BEGIN
  BEGIN
    UPDATE kovcheg.outbox_events
    SET payload = '{"fixture":"changed"}'::jsonb
    WHERE idempotency_key = 'runtime-claim-' || kovcheg.current_migration_version();
    RAISE EXCEPTION 'runtime changed a protected outbox payload';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

UPDATE kovcheg.outbox_events
SET delivered_at = clock_timestamp(),
    claim_token = NULL,
    claim_expires_at = NULL
WHERE idempotency_key = 'runtime-claim-' || kovcheg.current_migration_version();

SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1
    FROM kovcheg.outbox_events
    WHERE idempotency_key = 'runtime-claim-' || kovcheg.current_migration_version()
      AND delivered_at IS NOT NULL
      AND claim_token IS NULL
      AND claim_expires_at IS NULL
      AND attempt_count = 1
  ),
  'runtime must complete a claimed outbox event without changing its payload'
);

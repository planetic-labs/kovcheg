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

INSERT INTO kovcheg.messages (
  chat_id,
  sender_account_id,
  client_idempotency_key,
  content_fingerprint,
  body,
  correlation_id
)
SELECT
  target_chat.id,
  '00000000-0000-4000-8000-000000002001',
  'plan-message-' || series_number,
  'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  'Synthetic plan fixture ' || series_number,
  'database-plan-message-' || series_number
FROM (
  SELECT id
  FROM kovcheg.chats
  WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001'
  ORDER BY id
  LIMIT 1
) AS target_chat
CROSS JOIN generate_series(1, 1500) AS series_number;

INSERT INTO kovcheg.outbox_events (
  aggregate_type,
  aggregate_id,
  event_name,
  idempotency_key,
  correlation_id,
  migration_version,
  payload,
  delivered_at
)
SELECT
  'database',
  '00000000-0000-4000-8000-000000002001',
  'database.plan-delivered',
  'plan-delivered-' || series_number,
  'database-plan-delivered-' || series_number,
  kovcheg.current_migration_version(),
  jsonb_build_object('fixtureId', series_number),
  clock_timestamp()
FROM generate_series(1, 3000) AS series_number;

INSERT INTO kovcheg.outbox_events (
  aggregate_type,
  aggregate_id,
  event_name,
  idempotency_key,
  correlation_id,
  migration_version,
  payload
)
SELECT
  'database',
  '00000000-0000-4000-8000-000000002001',
  'database.plan-pending',
  'plan-pending-' || series_number,
  'database-plan-pending-' || series_number,
  kovcheg.current_migration_version(),
  jsonb_build_object('fixtureId', series_number)
FROM generate_series(1, 40) AS series_number;

INSERT INTO kovcheg.outbox_events (
  aggregate_type,
  aggregate_id,
  event_name,
  idempotency_key,
  correlation_id,
  migration_version,
  payload,
  claim_token,
  claim_expires_at
)
SELECT
  'database',
  '00000000-0000-4000-8000-000000002001',
  'database.plan-expired',
  'plan-expired-' || series_number,
  'database-plan-expired-' || series_number,
  kovcheg.current_migration_version(),
  jsonb_build_object('fixtureId', series_number),
  gen_random_uuid(),
  clock_timestamp() - interval '5 minutes'
FROM generate_series(1, 40) AS series_number;

ANALYZE kovcheg.messages;
ANALYZE kovcheg.outbox_events;

DO $$
DECLARE
  target_chat_id uuid;
  message_plan json;
  pending_plan json;
  expired_plan json;
  partition_relation_count integer;
BEGIN
  SELECT id INTO target_chat_id
  FROM kovcheg.chats
  WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001'
  ORDER BY id
  LIMIT 1;

  EXECUTE format(
    'EXPLAIN (FORMAT JSON) SELECT id, chat_sequence FROM kovcheg.messages WHERE chat_id = %L ORDER BY chat_sequence DESC LIMIT 20',
    target_chat_id
  ) INTO message_plan;

  SELECT count(*) INTO partition_relation_count
  FROM regexp_matches(message_plan::text, '"Relation Name": "messages_p[0-7]"', 'g');

  IF partition_relation_count <> 1 OR message_plan::text NOT LIKE '%Index Scan%' THEN
    RAISE EXCEPTION 'message history plan did not prune to one indexed partition: %', message_plan;
  END IF;

  EXPLAIN (FORMAT JSON)
  SELECT id
  FROM kovcheg.outbox_events
  WHERE delivered_at IS NULL
    AND claim_token IS NULL
    AND available_at <= statement_timestamp()
  ORDER BY available_at, occurred_at, id
  LIMIT 20
  INTO pending_plan;

  IF pending_plan::text NOT LIKE '%outbox_events_pending_idx%' THEN
    RAISE EXCEPTION 'pending outbox plan did not use its index: %', pending_plan;
  END IF;

  EXPLAIN (FORMAT JSON)
  SELECT id
  FROM kovcheg.outbox_events
  WHERE delivered_at IS NULL
    AND claim_token IS NOT NULL
    AND claim_expires_at <= statement_timestamp()
  ORDER BY claim_expires_at, id
  LIMIT 20
  INTO expired_plan;

  IF expired_plan::text NOT LIKE '%outbox_events_expired_claim_idx%' THEN
    RAISE EXCEPTION 'expired outbox claim plan did not use its index: %', expired_plan;
  END IF;
END;
$$;

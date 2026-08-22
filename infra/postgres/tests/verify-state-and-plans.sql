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
  (
    SELECT count(*) = 14 AND min(chat_sequence) = 1 AND max(chat_sequence) = 14
    FROM kovcheg.messages
    WHERE chat_id = (
      SELECT id FROM kovcheg.chats
      WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001'
      ORDER BY id
      LIMIT 1
    )
  ),
  'parallel row-counter allocation must be gap-free and unique'
);
SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 14
    FROM kovcheg.message_versions
    WHERE chat_id = (
      SELECT id FROM kovcheg.chats
      WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001'
      ORDER BY id
      LIMIT 1
    )
  ),
  'every message must have an initial immutable version'
);
SELECT pg_temp.assert_true(
  (SELECT count(*) >= 2 FROM kovcheg.audit_events)
  AND (SELECT count(*) >= 1 FROM kovcheg.operation_events),
  'provisioning and audit-writer events must be protected and queryable by migration role'
);
SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM kovcheg.outbox_events
    WHERE idempotency_key = 'outbox-message-001' AND delivered_at IS NULL
  ),
  'transactional outbox fixture must persist'
);

SET enable_seqscan = off;
DO $$
DECLARE
  target_chat_id uuid;
  message_plan json;
  outbox_plan json;
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
  WHERE delivered_at IS NULL AND available_at <= clock_timestamp()
  ORDER BY available_at, occurred_at, id
  LIMIT 20
  INTO outbox_plan;

  IF outbox_plan::text NOT LIKE '%outbox_events_pending_idx%' THEN
    RAISE EXCEPTION 'outbox claim plan did not use the pending index: %', outbox_plan;
  END IF;
END;
$$;
RESET enable_seqscan;

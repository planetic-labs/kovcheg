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
    SELECT count(*) > 0 AND min(chat_sequence) = 1 AND max(chat_sequence) = count(*)
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
    SELECT (
      SELECT count(*) FROM kovcheg.message_versions
      WHERE chat_id = target_chat.id
    ) = (
      SELECT count(*) FROM kovcheg.messages
      WHERE chat_id = target_chat.id
    )
    FROM (
      SELECT id FROM kovcheg.chats
      WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001'
      ORDER BY id
      LIMIT 1
    ) AS target_chat
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
    SELECT 1
    FROM kovcheg.outbox_events AS event
    JOIN kovcheg.messages AS message ON message.id = event.aggregate_id
    WHERE message.client_idempotency_key IN ('message-001', 'message-flow-001')
      AND event.event_name = 'message.created'
      AND event.delivered_at IS NULL
  ),
  'transactional outbox fixture must persist'
);

DO $$
BEGIN
  BEGIN
    UPDATE kovcheg.audit_events
    SET details = details
    WHERE id = (SELECT id FROM kovcheg.audit_events ORDER BY occurred_at LIMIT 1);
    RAISE EXCEPTION 'audit UPDATE bypassed its append-only trigger';
  EXCEPTION WHEN SQLSTATE '55000' THEN
    NULL;
  END;

  BEGIN
    DELETE FROM kovcheg.operation_events
    WHERE id = (SELECT id FROM kovcheg.operation_events ORDER BY occurred_at LIMIT 1);
    RAISE EXCEPTION 'operation DELETE bypassed its append-only trigger';
  EXCEPTION WHEN SQLSTATE '55000' THEN
    NULL;
  END;

  BEGIN
    TRUNCATE TABLE kovcheg.audit_events;
    RAISE EXCEPTION 'audit TRUNCATE bypassed its append-only trigger';
  EXCEPTION WHEN SQLSTATE '55000' THEN
    NULL;
  END;

  BEGIN
    TRUNCATE TABLE kovcheg.operation_events;
    RAISE EXCEPTION 'operation TRUNCATE bypassed its append-only trigger';
  EXCEPTION WHEN SQLSTATE '55000' THEN
    NULL;
  END;
END;
$$;

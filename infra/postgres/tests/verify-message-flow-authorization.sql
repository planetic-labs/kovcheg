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
  has_function_privilege(
    'kovcheg_app',
    'kovcheg.create_text_message(uuid,uuid,character varying,character varying,text,character varying)',
    'EXECUTE'
  ),
  'runtime must execute only the atomic message-flow entrypoint'
);
SELECT pg_temp.assert_true(
  NOT has_table_privilege('kovcheg_app', 'kovcheg.messages', 'INSERT')
  AND NOT has_table_privilege('kovcheg_app', 'kovcheg.outbox_events', 'INSERT')
  AND NOT has_table_privilege('kovcheg_app', 'kovcheg.audit_events', 'INSERT'),
  'runtime must not bypass message, outbox, or protected audit writes'
);
SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 1
    FROM kovcheg.audit_events AS audit
    JOIN kovcheg.messages AS message ON message.id = audit.target_id
    WHERE message.client_idempotency_key = 'message-flow-001'
      AND audit.action = 'message.created'
      AND audit.actor_account_id = message.sender_account_id
  ),
  'the atomic entrypoint must append exactly one protected audit event'
);

BEGIN;
UPDATE kovcheg.accounts
SET status = 'deactivated', deactivated_at = clock_timestamp()
WHERE id = '00000000-0000-4000-8000-000000002001';
DO $$
BEGIN
  BEGIN
    PERFORM kovcheg.create_text_message(
      (
        SELECT chat_id FROM kovcheg.messages
        WHERE client_idempotency_key = 'message-flow-001'
        ORDER BY created_at LIMIT 1
      ),
      '00000000-0000-4000-8000-000000002001',
      'message-flow-deactivated',
      'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
      'Synthetic deactivated message',
      'database-message-flow-deactivated'
    );
    RAISE EXCEPTION 'a deactivated account posted a message';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM kovcheg.create_text_message(
      (
        SELECT chat_id FROM kovcheg.messages
        WHERE client_idempotency_key = 'message-flow-001'
        ORDER BY created_at LIMIT 1
      ),
      '00000000-0000-4000-8000-000000002001',
      'message-flow-001',
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'Synthetic message-flow message',
      'database-message-flow-deactivated-replay'
    );
    RAISE EXCEPTION 'a deactivated account replayed an existing message';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;
ROLLBACK;

BEGIN;
UPDATE kovcheg.chat_memberships
SET status = 'revoked', revoked_at = clock_timestamp()
WHERE account_id = '00000000-0000-4000-8000-000000002001'
  AND chat_id = (
    SELECT chat_id FROM kovcheg.messages
    WHERE client_idempotency_key = 'message-flow-001'
    ORDER BY created_at LIMIT 1
  );
DO $$
BEGIN
  BEGIN
    PERFORM kovcheg.create_text_message(
      (
        SELECT chat_id FROM kovcheg.messages
        WHERE client_idempotency_key = 'message-flow-001'
        ORDER BY created_at LIMIT 1
      ),
      '00000000-0000-4000-8000-000000002001',
      'message-flow-001',
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'Synthetic message-flow message',
      'database-message-flow-revoked-replay'
    );
    RAISE EXCEPTION 'a revoked member replayed an existing message';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;
ROLLBACK;

BEGIN;
CREATE FUNCTION pg_temp.reject_message_audit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.correlation_id = 'database-message-flow-atomic-failure' THEN
    RAISE EXCEPTION 'synthetic audit failure' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER verify_reject_message_audit
BEFORE INSERT ON kovcheg.audit_events
FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_message_audit();

DO $$
DECLARE
  target_chat_id uuid;
  counter_before bigint;
  counter_after bigint;
BEGIN
  SELECT chat_id INTO target_chat_id
  FROM kovcheg.messages
  WHERE client_idempotency_key = 'message-flow-001'
  ORDER BY created_at
  LIMIT 1;
  SELECT next_sequence INTO counter_before
  FROM kovcheg.chat_counters WHERE chat_id = target_chat_id;

  BEGIN
    PERFORM kovcheg.create_text_message(
      target_chat_id,
      '00000000-0000-4000-8000-000000002001',
      'message-flow-atomic-failure',
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      'Synthetic atomic failure',
      'database-message-flow-atomic-failure'
    );
    RAISE EXCEPTION 'an audit failure did not abort message creation';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  SELECT next_sequence INTO counter_after
  FROM kovcheg.chat_counters WHERE chat_id = target_chat_id;
  IF counter_after <> counter_before
    OR EXISTS (
      SELECT 1 FROM kovcheg.messages
      WHERE client_idempotency_key = 'message-flow-atomic-failure'
    )
    OR EXISTS (
      SELECT 1 FROM kovcheg.outbox_events
      WHERE correlation_id = 'database-message-flow-atomic-failure'
    )
    OR EXISTS (
      SELECT 1 FROM kovcheg.audit_events
      WHERE correlation_id = 'database-message-flow-atomic-failure'
    )
  THEN
    RAISE EXCEPTION 'an audit failure left a partial message transaction';
  END IF;
END;
$$;
ROLLBACK;

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

CREATE FUNCTION pg_temp.create_test_text_message(
  p_chat_id uuid,
  p_operator_account_id uuid,
  p_client_idempotency_key varchar,
  p_content_fingerprint varchar,
  p_body text,
  p_correlation_id varchar
)
RETURNS TABLE (
  message_id uuid,
  message_chat_id uuid,
  sender_account_id uuid,
  chat_sequence bigint,
  client_idempotency_key varchar,
  message_body text,
  created_at timestamptz,
  was_created boolean
)
LANGUAGE plpgsql
AS $$
DECLARE
  session_id uuid;
BEGIN
  IF to_regprocedure(
    'kovcheg.create_text_message_for_session(uuid,uuid,uuid,uuid,character varying,character varying,text,character varying,timestamp with time zone)'
  ) IS NULL THEN
    RETURN QUERY
    SELECT *
    FROM kovcheg.create_text_message(
      p_chat_id,
      p_operator_account_id,
      p_client_idempotency_key,
      p_content_fingerprint,
      p_body,
      p_correlation_id
    );
    RETURN;
  END IF;

  session_id := CASE p_operator_account_id
    WHEN '00000000-0000-4000-8000-000000002001'::uuid
      THEN '00000000-0000-4000-8000-000000002201'::uuid
    WHEN '00000000-0000-4000-8000-000000002002'::uuid
      THEN '00000000-0000-4000-8000-000000002202'::uuid
    ELSE '00000000-0000-4000-8000-000000002299'::uuid
  END;

  RETURN QUERY EXECUTE
    'SELECT * FROM kovcheg.create_text_message_for_session($1,$2,$3,$4,$5,$6,$7,$8,$9)'
  USING
    p_chat_id,
    session_id,
    p_operator_account_id,
    NULL::uuid,
    p_client_idempotency_key,
    p_content_fingerprint,
    p_body,
    p_correlation_id,
    '2030-01-01 00:30:00+00'::timestamptz;
END;
$$;

DO $$
DECLARE
  account_id uuid;
BEGIN
  FOREACH account_id IN ARRAY ARRAY[
    '00000000-0000-4000-8000-000000002001'::uuid,
    '00000000-0000-4000-8000-000000002002'::uuid,
    '00000000-0000-4000-8000-000000002003'::uuid
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM kovcheg.accounts AS account WHERE account.id = account_id
    ) THEN
      PERFORM kovcheg.provision_account_with_starter_set(
        account_id,
        ('database-provision-' || account_id::text)::varchar
      );
    END IF;
  END LOOP;
END;
$$;

DO $$
DECLARE
  spoof_chat_id uuid;
BEGIN
  IF to_regprocedure(
    'kovcheg.create_text_message_for_session(uuid,uuid,uuid,uuid,character varying,character varying,text,character varying,timestamp with time zone)'
  ) IS NOT NULL THEN
    SELECT chat.id
    INTO STRICT spoof_chat_id
    FROM kovcheg.chats AS chat
    WHERE chat.provisioned_for_account_id = '00000000-0000-4000-8000-000000002003'
    ORDER BY chat.id
    LIMIT 1;

    BEGIN
      PERFORM kovcheg.create_text_message(
        spoof_chat_id,
        '00000000-0000-4000-8000-000000002003',
        'message-flow-sessionless-spoof',
        '9999999999999999999999999999999999999999999999999999999999999999',
        'Synthetic sessionless spoof attempt',
        'database-message-flow-sessionless-spoof'
      );
      RAISE EXCEPTION 'runtime used the sessionless entrypoint to impersonate an active person';
    EXCEPTION WHEN insufficient_privilege THEN
      NULL;
    END;
  END IF;
END;
$$;

CREATE TEMP TABLE first_message_flow_result AS
SELECT *
FROM pg_temp.create_test_text_message(
  (
    SELECT id FROM kovcheg.chats
    WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001'
    ORDER BY id LIMIT 1
  ),
  '00000000-0000-4000-8000-000000002001',
  'message-flow-001',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'Synthetic message-flow message',
  'database-message-flow-created'
);

SELECT pg_temp.assert_true(
  (SELECT was_created FROM first_message_flow_result),
  'the first message-flow call must create a message'
);
SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 1
    FROM kovcheg.message_versions AS version
    JOIN first_message_flow_result AS result
      ON version.chat_id = result.message_chat_id
     AND version.message_id = result.message_id
     AND version.version_number = 1
  ),
  'message creation must atomically create the initial version'
);
SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 1
    FROM kovcheg.outbox_events AS event
    JOIN first_message_flow_result AS result ON event.aggregate_id = result.message_id
    WHERE event.event_name = 'message.created'
      AND event.correlation_id = 'database-message-flow-created'
      AND event.payload = (
        jsonb_build_object(
        'chatId', result.message_chat_id,
        'messageId', result.message_id,
        'chatSequence', result.chat_sequence
        ) || CASE
          WHEN to_regprocedure(
            'kovcheg.create_text_message_for_session(uuid,uuid,uuid,uuid,character varying,character varying,text,character varying,timestamp with time zone)'
          ) IS NULL THEN '{}'::jsonb
          ELSE jsonb_build_object('senderAccountId', result.sender_account_id)
        END
      )
  ),
  'message creation must atomically create one sanitized outbox event'
);

CREATE TEMP TABLE replayed_message_flow_result AS
SELECT *
FROM pg_temp.create_test_text_message(
  (SELECT message_chat_id FROM first_message_flow_result),
  '00000000-0000-4000-8000-000000002001',
  'message-flow-001',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'Synthetic message-flow message',
  'database-message-flow-replayed'
);

SELECT pg_temp.assert_true(
  NOT (SELECT was_created FROM replayed_message_flow_result)
  AND (
    SELECT first_result.message_id = replayed_result.message_id
      AND first_result.chat_sequence = replayed_result.chat_sequence
    FROM first_message_flow_result AS first_result
    CROSS JOIN replayed_message_flow_result AS replayed_result
  ),
  'an identical retry must return the original message without a duplicate'
);
SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM kovcheg.outbox_events
    WHERE correlation_id = 'database-message-flow-replayed'
  ),
  'an identical retry must not create a second outbox event'
);

DO $$
BEGIN
  BEGIN
    PERFORM pg_temp.create_test_text_message(
      (SELECT message_chat_id FROM first_message_flow_result),
      '00000000-0000-4000-8000-000000002001',
      'message-flow-001',
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      'Synthetic conflicting message',
      'database-message-flow-conflict'
    );
    RAISE EXCEPTION 'idempotency key reuse with different content was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;

  BEGIN
    PERFORM pg_temp.create_test_text_message(
      (SELECT message_chat_id FROM first_message_flow_result),
      '00000000-0000-4000-8000-000000002002',
      'message-flow-nonmember',
      'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      'Synthetic unauthorized message',
      'database-message-flow-nonmember'
    );
    RAISE EXCEPTION 'a non-member posted to a direct chat';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    EXECUTE $statement$
      INSERT INTO kovcheg.messages (
        chat_id,
        sender_account_id,
        client_idempotency_key,
        content_fingerprint,
        body,
        correlation_id
      ) VALUES (
        '00000000-0000-4000-8000-000000001201',
        '00000000-0000-4000-8000-000000001001',
        'message-flow-direct-insert',
        'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        'Synthetic direct insert',
        'database-message-flow-direct-insert'
      )
    $statement$;
    RAISE EXCEPTION 'runtime inserted a message outside the atomic entrypoint';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    INSERT INTO kovcheg.outbox_events (
      aggregate_type,
      aggregate_id,
      event_name,
      idempotency_key,
      correlation_id,
      migration_version,
      payload
    ) VALUES (
      'message',
      '00000000-0000-4000-8000-000000002001',
      'message.direct-insert',
      'message-flow-direct-outbox',
      'database-message-flow-direct-outbox',
      '0004',
      '{}'::jsonb
    );
    RAISE EXCEPTION 'runtime inserted an outbox event outside the atomic entrypoint';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

INSERT INTO kovcheg.chat_read_states (chat_id, account_id, last_read_sequence)
SELECT
  message_chat_id,
  '00000000-0000-4000-8000-000000002001',
  chat_sequence
FROM first_message_flow_result
ON CONFLICT (chat_id, account_id) DO UPDATE
SET last_read_sequence = EXCLUDED.last_read_sequence,
    updated_at = clock_timestamp();

SELECT pg_temp.assert_true(
  kovcheg.can_account_read_chat(
    '00000000-0000-4000-8000-000000002001',
    (SELECT message_chat_id FROM first_message_flow_result)
  ),
  'the active member must retain read access to the message-flow chat'
);

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

CREATE FUNCTION pg_temp.assert_authorization_denied(
  session_id uuid,
  operator_account_id uuid,
  persona_account_id uuid,
  assertion_message text
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM *
  FROM kovcheg.authorize_system_persona_action(
    session_id,
    operator_account_id,
    persona_account_id,
    '2030-01-01 01:00:00+00'
  );
  RAISE EXCEPTION 'assertion failed: %', assertion_message;
EXCEPTION WHEN insufficient_privilege THEN
  IF SQLERRM <> 'persona authorization failed' THEN
    RAISE EXCEPTION 'authorization failure was not neutral';
  END IF;
END;
$$;

SELECT pg_temp.assert_true(
  current_user = 'kovcheg_app'
  AND has_function_privilege(
    current_user,
    'kovcheg.authorize_system_persona_action(uuid,uuid,uuid,timestamp with time zone)',
    'EXECUTE'
  ),
  'only the general runtime path under test may call persona authorization'
);

SELECT pg_temp.assert_true(
  NOT has_table_privilege(
    current_user,
    'kovcheg.system_persona_operator_grants',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    current_user,
    'kovcheg.auth_sessions',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    current_user,
    'kovcheg.account_auth_profiles',
    'SELECT,INSERT,UPDATE,DELETE'
  ),
  'the runtime must not receive direct grant or auth-state DML'
);

SELECT pg_temp.assert_true(
  (
    SELECT operator_account_id = '00000000-0000-4000-8000-000000009001'
      AND persona_account_id = '00000000-0000-4000-8000-000000009101'
    FROM kovcheg.authorize_system_persona_action(
      '00000000-0000-4000-8000-000000009201',
      '00000000-0000-4000-8000-000000009001',
      '00000000-0000-4000-8000-000000009101',
      '2030-01-01 01:00:00+00'
    )
  ),
  'one active personal session and exact active grant must authorize distinct identities'
);

SELECT pg_temp.assert_true(
  (
    SELECT operator_account_id = '00000000-0000-4000-8000-000000009002'
      AND persona_account_id = '00000000-0000-4000-8000-000000009101'
    FROM kovcheg.authorize_system_persona_action(
      '00000000-0000-4000-8000-000000009202',
      '00000000-0000-4000-8000-000000009002',
      '00000000-0000-4000-8000-000000009101',
      '2030-01-01 01:00:00+00'
    )
  ),
  'two operators must authorize independently for the same persona'
);

SELECT pg_temp.assert_authorization_denied(
  '00000000-0000-4000-8000-000000009299',
  '00000000-0000-4000-8000-000000009001',
  '00000000-0000-4000-8000-000000009101',
  'a missing session was accepted'
);
SELECT pg_temp.assert_authorization_denied(
  '00000000-0000-4000-8000-000000009204',
  '00000000-0000-4000-8000-000000009001',
  '00000000-0000-4000-8000-000000009101',
  'an expired session was accepted'
);
SELECT pg_temp.assert_authorization_denied(
  '00000000-0000-4000-8000-000000009205',
  '00000000-0000-4000-8000-000000009001',
  '00000000-0000-4000-8000-000000009101',
  'a revoked session was accepted'
);
SELECT pg_temp.assert_authorization_denied(
  '00000000-0000-4000-8000-000000009201',
  '00000000-0000-4000-8000-000000009002',
  '00000000-0000-4000-8000-000000009101',
  'a session-account mismatch was accepted'
);
SELECT pg_temp.assert_authorization_denied(
  '00000000-0000-4000-8000-000000009201',
  '00000000-0000-4000-8000-000000009001',
  '00000000-0000-4000-8000-000000009102',
  'a revoked pair or another operator grant was accepted'
);
SELECT pg_temp.assert_authorization_denied(
  '00000000-0000-4000-8000-000000009201',
  '00000000-0000-4000-8000-000000009001',
  '00000000-0000-4000-8000-000000009199',
  'a missing grant was accepted'
);
SELECT pg_temp.assert_authorization_denied(
  '00000000-0000-4000-8000-000000009201',
  '00000000-0000-4000-8000-000000009001',
  '00000000-0000-4000-8000-000000009002',
  'a person account was accepted as a system persona'
);
SELECT pg_temp.assert_authorization_denied(
  '00000000-0000-4000-8000-000000009203',
  '00000000-0000-4000-8000-000000009003',
  '00000000-0000-4000-8000-000000009101',
  'an inactive operator was accepted'
);
SELECT pg_temp.assert_authorization_denied(
  '00000000-0000-4000-8000-000000009201',
  '00000000-0000-4000-8000-000000009001',
  '00000000-0000-4000-8000-000000009103',
  'an inactive persona was accepted'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.outbox_events AS event
    WHERE event.payload ? 'operatorAccountId'
  ),
  'ordinary personal message outbox payloads must not expose the operator UUID'
);

CREATE TEMP TABLE persona_message_result AS
SELECT *
FROM kovcheg.create_text_message_for_session(
  '00000000-0000-4000-8000-000000009401',
  '00000000-0000-4000-8000-000000009201',
  '00000000-0000-4000-8000-000000009001',
  '00000000-0000-4000-8000-000000009101',
  'persona-message-audit-001',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'Synthetic persona message',
  'persona-message-audit-created',
  '2030-01-01 00:30:00+00'
);

SELECT pg_temp.assert_true(
  (SELECT was_created FROM persona_message_result)
  AND (
    SELECT sender_account_id = '00000000-0000-4000-8000-000000009101'
    FROM persona_message_result
  ),
  'the authorized persona must be the persisted public sender'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 1
      AND bool_and(
        event.payload = jsonb_build_object(
          'chatId', result.message_chat_id,
          'messageId', result.message_id,
          'chatSequence', result.chat_sequence,
          'senderAccountId', result.sender_account_id
        )
      )
      AND bool_and(NOT event.payload ? 'operatorAccountId')
    FROM kovcheg.outbox_events AS event
    CROSS JOIN persona_message_result AS result
    WHERE event.aggregate_id = result.message_id
      AND event.event_name = 'message.created'
  ),
  'the persona outbox event must expose only the public sender identity'
);

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
    SELECT count(*) = 4
      AND count(DISTINCT message.chat_id) = 4
      AND bool_and(message.sender_account_id = membership.account_id)
    FROM kovcheg.messages AS message
    JOIN kovcheg.chat_memberships AS membership
      ON membership.chat_id = message.chat_id
     AND membership.account_id = message.sender_account_id
     AND membership.role = 'synthetic_system'
    WHERE message.client_idempotency_key LIKE 'privacy-race-%-before'
  ),
  'each authorization-first race must commit one message from its public persona'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 4
      AND bool_and(audit.actor_account_id <> message.sender_account_id)
      AND bool_and(audit.actor_account_id = membership.account_id)
    FROM kovcheg.messages AS message
    JOIN kovcheg.audit_events AS audit
      ON audit.target_id = message.id
     AND audit.action = 'message.created'
    JOIN kovcheg.chat_memberships AS membership
      ON membership.chat_id = message.chat_id
     AND membership.account_id = audit.actor_account_id
     AND membership.role = 'member'
    WHERE message.client_idempotency_key LIKE 'privacy-race-%-before'
  ),
  'protected audit must retain the personal operator separately from the public persona sender'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 4
      AND bool_and(
        event.payload = jsonb_build_object(
          'chatId', message.chat_id,
          'messageId', message.id,
          'chatSequence', message.chat_sequence,
          'senderAccountId', message.sender_account_id
        )
      )
      AND bool_and(NOT event.payload ? 'operatorAccountId')
      AND bool_and(NOT event.payload ? 'actorAccountId')
    FROM kovcheg.messages AS message
    JOIN kovcheg.outbox_events AS event
      ON event.aggregate_id = message.id
     AND event.event_name = 'message.created'
    WHERE message.client_idempotency_key LIKE 'privacy-race-%-before'
  ),
  'outbox events must contain only the public sender identity and public message metadata'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.messages
    WHERE client_idempotency_key LIKE 'privacy-race-%-after'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.outbox_events
    WHERE correlation_id LIKE 'privacy-race-%-after'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events
    WHERE correlation_id LIKE 'privacy-race-%-after'
  ),
  'an authorization attempt after a completed mutation must leave no message, outbox, or audit state'
);

SELECT pg_temp.assert_true(
  (
    SELECT status = 'revoked'
    FROM kovcheg.system_persona_operator_grants
    WHERE operator_account_id = '00000000-0000-4000-8000-000000009011'
      AND persona_account_id = '00000000-0000-4000-8000-000000009111'
  )
  AND (
    SELECT status = 'deactivated'
    FROM kovcheg.accounts
    WHERE id = '00000000-0000-4000-8000-000000009012'
  )
  AND (
    SELECT status = 'deactivated'
    FROM kovcheg.accounts
    WHERE id = '00000000-0000-4000-8000-000000009113'
  )
  AND (
    SELECT revoked_at IS NOT NULL
    FROM kovcheg.auth_sessions
    WHERE id = '00000000-0000-4000-8000-000000009214'
  ),
  'all four authorization-state mutations must complete after the first action'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.account_auth_profiles AS profile
    WHERE profile.account_id IN (
      '00000000-0000-4000-8000-000000009111',
      '00000000-0000-4000-8000-000000009112',
      '00000000-0000-4000-8000-000000009113',
      '00000000-0000-4000-8000-000000009114'
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_sessions AS session
    WHERE session.account_id IN (
      '00000000-0000-4000-8000-000000009111',
      '00000000-0000-4000-8000-000000009112',
      '00000000-0000-4000-8000-000000009113',
      '00000000-0000-4000-8000-000000009114'
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_email_challenges AS challenge
    WHERE challenge.account_id IN (
      '00000000-0000-4000-8000-000000009111',
      '00000000-0000-4000-8000-000000009112',
      '00000000-0000-4000-8000-000000009113',
      '00000000-0000-4000-8000-000000009114'
    )
  ),
  'system personas must remain outside auth profiles, sessions, and email challenges'
);

SELECT pg_temp.assert_true(
  NOT has_table_privilege('kovcheg_app', 'kovcheg.audit_events', 'SELECT,INSERT,UPDATE,DELETE')
  AND NOT has_table_privilege(
    'kovcheg_app',
    'kovcheg.system_persona_operator_grants',
    'SELECT,INSERT,UPDATE,DELETE'
  ),
  'general runtime must not read protected audit actors or authorization grants'
);

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

DO $$
BEGIN
  PERFORM *
  FROM kovcheg.authorize_system_persona_action(
    '00000000-0000-4000-8000-000000009201',
    '00000000-0000-4000-8000-000000009001',
    '00000000-0000-4000-8000-000000009101',
    '2030-01-01 01:02:00+00'
  );
  RAISE EXCEPTION 'the next authorization ignored the revoked exact grant';
EXCEPTION WHEN insufficient_privilege THEN
  IF SQLERRM <> 'persona authorization failed' THEN
    RAISE EXCEPTION 'authorization failure was not neutral';
  END IF;
END;
$$;

DO $$
BEGIN
  PERFORM *
  FROM kovcheg.create_text_message_for_session(
    '00000000-0000-4000-8000-000000009401',
    '00000000-0000-4000-8000-000000009201',
    '00000000-0000-4000-8000-000000009001',
    '00000000-0000-4000-8000-000000009101',
    'persona-message-audit-revoked',
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'Synthetic revoked persona message',
    'persona-message-audit-revoked',
    '2030-01-01 01:02:00+00'
  );
  RAISE EXCEPTION 'a revoked persona grant created a message';
EXCEPTION WHEN insufficient_privilege THEN
  IF SQLERRM <> 'persona authorization failed' THEN
    RAISE EXCEPTION 'revoked persona message failure was not neutral';
  END IF;
END;
$$;

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.messages
    WHERE client_idempotency_key = 'persona-message-audit-revoked'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.outbox_events
    WHERE correlation_id = 'persona-message-audit-revoked'
  ),
  'revoked persona authorization must leave no message or outbox state'
);

SELECT pg_temp.assert_true(
  (
    SELECT operator_account_id = '00000000-0000-4000-8000-000000009002'
      AND persona_account_id = '00000000-0000-4000-8000-000000009101'
    FROM kovcheg.authorize_system_persona_action(
      '00000000-0000-4000-8000-000000009202',
      '00000000-0000-4000-8000-000000009002',
      '00000000-0000-4000-8000-000000009101',
      '2030-01-01 01:02:00+00'
    )
  ),
  'revoking one operator must not affect the other operator'
);

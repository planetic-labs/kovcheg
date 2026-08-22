SELECT * FROM kovcheg.provision_account_with_starter_set(
  '00000000-0000-4000-8000-000000002001',
  'database-provision-001'
);

DO $$
DECLARE
  direct_chat_count integer;
  membership_count integer;
BEGIN
  SELECT count(*)::integer INTO direct_chat_count
  FROM kovcheg.chats
  WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001';

  SELECT count(*)::integer INTO membership_count
  FROM kovcheg.chat_memberships
  WHERE account_id = '00000000-0000-4000-8000-000000002001' AND status = 'active';

  IF direct_chat_count <> 3 OR membership_count <> 4 THEN
    RAISE EXCEPTION 'starter provisioning did not create the required atomic set';
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
  id,
  '00000000-0000-4000-8000-000000002001',
  'message-001',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'Synthetic first message',
  'database-message-001'
FROM kovcheg.chats
WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001'
ORDER BY id
LIMIT 1;

DO $$
BEGIN
  BEGIN
    INSERT INTO kovcheg.messages (
      chat_id,
      sender_account_id,
      client_idempotency_key,
      content_fingerprint,
      body,
      correlation_id
    )
    SELECT
      id,
      '00000000-0000-4000-8000-000000002001',
      'message-001',
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      'Synthetic conflicting message',
      'database-message-conflict'
    FROM kovcheg.chats
    WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001'
    ORDER BY id
    LIMIT 1;
    RAISE EXCEPTION 'duplicate idempotency key was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;
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
  id,
  '00000000-0000-4000-8000-000000002001',
  'message-002',
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'Synthetic second message',
  'database-message-002'
FROM kovcheg.chats
WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001'
ORDER BY id
LIMIT 1;

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
  'message',
  id,
  'message.created',
  'outbox-message-001',
  'database-message-001',
  kovcheg.current_migration_version(),
  '{"fixture":"synthetic"}'::jsonb
FROM kovcheg.messages
WHERE client_idempotency_key = 'message-001';

INSERT INTO kovcheg.chat_read_states (chat_id, account_id, last_read_sequence)
SELECT
  id,
  '00000000-0000-4000-8000-000000002001',
  1
FROM kovcheg.chats
WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001'
ORDER BY id
LIMIT 1;

UPDATE kovcheg.chat_read_states
SET last_read_sequence = 2, updated_at = clock_timestamp()
WHERE account_id = '00000000-0000-4000-8000-000000002001';

DO $$
BEGIN
  BEGIN
    EXECUTE $statement$
      INSERT INTO kovcheg.audit_events (
        correlation_id,
        migration_version,
        action,
        target_type,
        outcome
      ) VALUES ('runtime-direct-audit', '0001', 'runtime.direct', 'test', 'success')
    $statement$;
    RAISE EXCEPTION 'runtime wrote directly to the audit table';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    INSERT INTO kovcheg.chat_memberships (chat_id, account_id)
    VALUES (
      '00000000-0000-4000-8000-000000001201',
      '00000000-0000-4000-8000-000000002001'
    );
    RAISE EXCEPTION 'runtime changed membership directly';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

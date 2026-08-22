CREATE FUNCTION kovcheg.create_text_message(
  p_chat_id uuid,
  p_sender_account_id uuid,
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
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  migration_version text;
BEGIN
  PERFORM 1
  FROM kovcheg.accounts AS account
  JOIN kovcheg.chat_memberships AS membership
    ON membership.account_id = account.id
  JOIN kovcheg.chats AS chat ON chat.id = membership.chat_id
  WHERE account.id = p_sender_account_id
    AND account.status = 'active'
    AND membership.chat_id = p_chat_id
    AND membership.status = 'active'
  FOR SHARE OF account, membership, chat;

  IF NOT FOUND OR NOT kovcheg.can_account_post_to_chat(p_sender_account_id, p_chat_id) THEN
    RAISE EXCEPTION 'account cannot post to chat' USING ERRCODE = '42501';
  END IF;

  INSERT INTO kovcheg.messages (
    chat_id,
    sender_account_id,
    client_idempotency_key,
    content_fingerprint,
    body,
    correlation_id
  ) VALUES (
    p_chat_id,
    p_sender_account_id,
    p_client_idempotency_key,
    p_content_fingerprint,
    p_body,
    p_correlation_id
  )
  RETURNING
    id,
    chat_id,
    messages.sender_account_id,
    messages.chat_sequence,
    messages.client_idempotency_key,
    body,
    messages.created_at
  INTO
    message_id,
    message_chat_id,
    sender_account_id,
    chat_sequence,
    client_idempotency_key,
    message_body,
    created_at;

  was_created := FOUND;

  IF NOT was_created THEN
    SELECT
      message.id,
      message.chat_id,
      message.sender_account_id,
      message.chat_sequence,
      message.client_idempotency_key,
      message.body,
      message.created_at
    INTO STRICT
      message_id,
      message_chat_id,
      sender_account_id,
      chat_sequence,
      client_idempotency_key,
      message_body,
      created_at
    FROM kovcheg.messages AS message
    WHERE message.chat_id = p_chat_id
      AND message.sender_account_id = p_sender_account_id
      AND message.client_idempotency_key = p_client_idempotency_key;

    RETURN NEXT;
    RETURN;
  END IF;

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

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
    message_id,
    'message.created',
    'message.created:' || message_id::text,
    p_correlation_id,
    migration_version,
    jsonb_build_object(
      'chatId', message_chat_id,
      'messageId', message_id,
      'chatSequence', chat_sequence
    )
  );

  INSERT INTO kovcheg.audit_events (
    correlation_id,
    migration_version,
    actor_account_id,
    action,
    target_type,
    target_id,
    outcome,
    details
  ) VALUES (
    p_correlation_id,
    migration_version,
    p_sender_account_id,
    'message.created',
    'message',
    message_id,
    'success',
    jsonb_build_object(
      'chatId', message_chat_id,
      'chatSequence', chat_sequence
    )
  );

  RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.create_text_message(
  uuid,
  uuid,
  varchar,
  varchar,
  text,
  varchar
) FROM PUBLIC;

REVOKE INSERT ON kovcheg.messages, kovcheg.outbox_events FROM kovcheg_runtime;

GRANT EXECUTE ON FUNCTION kovcheg.create_text_message(
  uuid,
  uuid,
  varchar,
  varchar,
  text,
  varchar
) TO kovcheg_runtime;

CREATE FUNCTION kovcheg.write_text_message(
  p_chat_id uuid,
  p_actor_account_id uuid,
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
  actor_kind kovcheg.account_kind;
  migration_version text;
  sender_kind kovcheg.account_kind;
BEGIN
  SELECT account.kind
  INTO actor_kind
  FROM kovcheg.accounts AS account
  WHERE account.id = p_actor_account_id
    AND account.status = 'active';

  SELECT account.kind
  INTO sender_kind
  FROM kovcheg.accounts AS account
  WHERE account.id = p_sender_account_id
    AND account.status = 'active';

  IF actor_kind IS DISTINCT FROM 'person'
    OR (
      p_sender_account_id = p_actor_account_id
      AND sender_kind IS DISTINCT FROM 'person'
    )
    OR (
      p_sender_account_id <> p_actor_account_id
      AND sender_kind IS DISTINCT FROM 'synthetic_system'
    )
    OR NOT kovcheg.can_account_post_to_chat(p_actor_account_id, p_chat_id)
    OR NOT kovcheg.can_account_post_to_chat(p_sender_account_id, p_chat_id)
  THEN
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
      'chatSequence', chat_sequence,
      'senderAccountId', sender_account_id
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
    p_actor_account_id,
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

REVOKE ALL ON FUNCTION kovcheg.write_text_message(
  uuid, uuid, uuid, varchar, varchar, text, varchar
) FROM PUBLIC;

CREATE OR REPLACE FUNCTION kovcheg.create_text_message(
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
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT *
  FROM kovcheg.write_text_message(
    p_chat_id,
    p_sender_account_id,
    p_sender_account_id,
    p_client_idempotency_key,
    p_content_fingerprint,
    p_body,
    p_correlation_id
  );
$$;

CREATE FUNCTION kovcheg.create_text_message_for_session(
  p_chat_id uuid,
  p_session_id uuid,
  p_operator_account_id uuid,
  p_persona_account_id uuid,
  p_client_idempotency_key varchar,
  p_content_fingerprint varchar,
  p_body text,
  p_correlation_id varchar,
  p_now timestamptz
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
  authorized_operator_account_id uuid;
  authorized_persona_account_id uuid;
  sender_account_id_value uuid;
BEGIN
  IF p_persona_account_id IS NULL THEN
    SELECT account.id
    INTO authorized_operator_account_id
    FROM kovcheg.auth_sessions AS session
    JOIN kovcheg.account_auth_profiles AS profile
      ON profile.account_id = session.account_id
    JOIN kovcheg.accounts AS account
      ON account.id = profile.account_id
    WHERE session.id = p_session_id
      AND session.account_id = p_operator_account_id
      AND session.revoked_at IS NULL
      AND p_now >= session.issued_at
      AND p_now < session.idle_expires_at
      AND p_now < session.absolute_expires_at
      AND account.id = p_operator_account_id
      AND account.kind = 'person'
      AND account.status = 'active';

    IF NOT FOUND THEN
      RAISE EXCEPTION 'message actor authorization failed' USING ERRCODE = '42501';
    END IF;
    sender_account_id_value := authorized_operator_account_id;
  ELSE
    SELECT operator_account_id, persona_account_id
    INTO authorized_operator_account_id, authorized_persona_account_id
    FROM kovcheg.authorize_system_persona_action(
      p_session_id,
      p_operator_account_id,
      p_persona_account_id,
      p_now
    );
    sender_account_id_value := authorized_persona_account_id;
  END IF;

  RETURN QUERY
  SELECT *
  FROM kovcheg.write_text_message(
    p_chat_id,
    authorized_operator_account_id,
    sender_account_id_value,
    p_client_idempotency_key,
    p_content_fingerprint,
    p_body,
    p_correlation_id
  );
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.create_text_message(
  uuid, uuid, varchar, varchar, text, varchar
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.create_text_message(
  uuid, uuid, varchar, varchar, text, varchar
) FROM kovcheg_runtime;
REVOKE ALL ON FUNCTION kovcheg.create_text_message_for_session(
  uuid, uuid, uuid, uuid, varchar, varchar, text, varchar, timestamptz
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION kovcheg.create_text_message_for_session(
  uuid, uuid, uuid, uuid, varchar, varchar, text, varchar, timestamptz
) TO kovcheg_runtime;

COMMENT ON FUNCTION kovcheg.create_text_message(
  uuid, uuid, varchar, varchar, text, varchar
) IS
  'Historical migration compatibility only. Runtime message creation must use the session-bound entrypoint.';

COMMENT ON COLUMN kovcheg.outbox_events.payload IS
  'Sanitized technical identifiers, public sender account identifiers, and counters only; no message text, personal operator identity, contact data, authentication material, credentials, or secrets.';

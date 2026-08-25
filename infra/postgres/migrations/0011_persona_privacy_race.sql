CREATE OR REPLACE FUNCTION kovcheg.authorize_system_persona_action(
  p_session_id uuid,
  p_operator_account_id uuid,
  p_persona_account_id uuid,
  p_now timestamptz
)
RETURNS TABLE (
  operator_account_id uuid,
  persona_account_id uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  IF p_session_id IS NULL
    OR p_operator_account_id IS NULL
    OR p_persona_account_id IS NULL
    OR p_now IS NULL
  THEN
    RAISE EXCEPTION 'persona authorization failed' USING ERRCODE = '42501';
  END IF;

  PERFORM 1
  FROM kovcheg.accounts AS operator_account
  WHERE operator_account.id = p_operator_account_id
    AND operator_account.kind = 'person'
    AND operator_account.status = 'active'
  FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'persona authorization failed' USING ERRCODE = '42501';
  END IF;

  PERFORM 1
  FROM kovcheg.auth_sessions AS session
  JOIN kovcheg.account_auth_profiles AS profile
    ON profile.account_id = session.account_id
  WHERE session.id = p_session_id
    AND session.account_id = p_operator_account_id
    AND session.revoked_at IS NULL
    AND p_now >= session.issued_at
    AND p_now < session.idle_expires_at
    AND p_now < session.absolute_expires_at
  FOR SHARE OF session;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'persona authorization failed' USING ERRCODE = '42501';
  END IF;

  PERFORM 1
  FROM kovcheg.accounts AS persona_account
  WHERE persona_account.id = p_persona_account_id
    AND persona_account.kind = 'synthetic_system'
    AND persona_account.status = 'active'
  FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'persona authorization failed' USING ERRCODE = '42501';
  END IF;

  PERFORM 1
  FROM kovcheg.system_persona_operator_grants AS operator_grant
  WHERE operator_grant.operator_account_id = p_operator_account_id
    AND operator_grant.persona_account_id = p_persona_account_id
    AND operator_grant.status = 'active'
  FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'persona authorization failed' USING ERRCODE = '42501';
  END IF;

  RETURN QUERY SELECT p_operator_account_id, p_persona_account_id;
END;
$$;

CREATE OR REPLACE FUNCTION kovcheg.create_text_message_for_session(
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
    PERFORM 1
    FROM kovcheg.accounts AS operator_account
    WHERE operator_account.id = p_operator_account_id
      AND operator_account.kind = 'person'
      AND operator_account.status = 'active'
    FOR SHARE;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'message actor authorization failed' USING ERRCODE = '42501';
    END IF;

    SELECT session.account_id
    INTO authorized_operator_account_id
    FROM kovcheg.auth_sessions AS session
    JOIN kovcheg.account_auth_profiles AS profile
      ON profile.account_id = session.account_id
    WHERE session.id = p_session_id
      AND session.account_id = p_operator_account_id
      AND session.revoked_at IS NULL
      AND p_now >= session.issued_at
      AND p_now < session.idle_expires_at
      AND p_now < session.absolute_expires_at
    FOR SHARE OF session;

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

REVOKE ALL ON FUNCTION kovcheg.authorize_system_persona_action(
  uuid, uuid, uuid, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION kovcheg.create_text_message_for_session(
  uuid, uuid, uuid, uuid, varchar, varchar, text, varchar, timestamptz
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION kovcheg.authorize_system_persona_action(
  uuid, uuid, uuid, timestamptz
) TO kovcheg_runtime;
GRANT EXECUTE ON FUNCTION kovcheg.create_text_message_for_session(
  uuid, uuid, uuid, uuid, varchar, varchar, text, varchar, timestamptz
) TO kovcheg_runtime;

COMMENT ON FUNCTION kovcheg.authorize_system_persona_action(
  uuid, uuid, uuid, timestamptz
) IS
  'Locks the current operator, session, persona, and exact grant for a transaction-scoped act-as authorization.';

COMMENT ON FUNCTION kovcheg.create_text_message_for_session(
  uuid, uuid, uuid, uuid, varchar, varchar, text, varchar, timestamptz
) IS
  'Creates one personal or act-as message while holding authorization-state locks through the atomic message, outbox, and audit write.';

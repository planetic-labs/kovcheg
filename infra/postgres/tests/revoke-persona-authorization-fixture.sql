DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events AS audit
    JOIN kovcheg.messages AS message ON message.id = audit.target_id
    WHERE message.client_idempotency_key = 'persona-message-audit-001'
      AND message.sender_account_id = '00000000-0000-4000-8000-000000009101'
      AND audit.action = 'message.created'
      AND audit.actor_account_id = '00000000-0000-4000-8000-000000009001'
  ) THEN
    RAISE EXCEPTION 'the protected message audit did not preserve the personal operator';
  END IF;

  UPDATE kovcheg.system_persona_operator_grants
  SET status = 'revoked',
      revoked_at = '2030-01-01 01:01:00+00',
      revoked_by_account_id = '00000000-0000-4000-8000-000000009002',
      updated_at = '2030-01-01 01:01:00+00'
  WHERE operator_account_id = '00000000-0000-4000-8000-000000009001'
    AND persona_account_id = '00000000-0000-4000-8000-000000009101';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'the authorization fixture grant was unavailable for revocation';
  END IF;
END;
$$;

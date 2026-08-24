DO $$
BEGIN
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

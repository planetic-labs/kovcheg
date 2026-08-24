CREATE FUNCTION kovcheg.authorize_system_persona_action(
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
  RETURN QUERY
  SELECT
    operator_account.id,
    persona_account.id
  FROM kovcheg.auth_sessions AS session
  JOIN kovcheg.account_auth_profiles AS profile
    ON profile.account_id = session.account_id
  JOIN kovcheg.accounts AS operator_account
    ON operator_account.id = profile.account_id
  JOIN kovcheg.system_persona_operator_grants AS operator_grant
    ON operator_grant.operator_account_id = operator_account.id
   AND operator_grant.persona_account_id = p_persona_account_id
  JOIN kovcheg.accounts AS persona_account
    ON persona_account.id = operator_grant.persona_account_id
  WHERE session.id = p_session_id
    AND session.account_id = p_operator_account_id
    AND session.revoked_at IS NULL
    AND p_now >= session.issued_at
    AND p_now < session.idle_expires_at
    AND p_now < session.absolute_expires_at
    AND operator_account.id = p_operator_account_id
    AND operator_account.kind = 'person'
    AND operator_account.status = 'active'
    AND persona_account.kind = 'synthetic_system'
    AND persona_account.status = 'active'
    AND operator_grant.status = 'active';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'persona authorization failed' USING ERRCODE = '42501';
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.authorize_system_persona_action(
  uuid, uuid, uuid, timestamptz
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION kovcheg.authorize_system_persona_action(
  uuid, uuid, uuid, timestamptz
) TO kovcheg_runtime;

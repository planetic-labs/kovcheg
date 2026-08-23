CREATE FUNCTION kovcheg.validate_auth_session(
  p_token_verifier text,
  p_now timestamptz
)
RETURNS TABLE (
  account_id uuid,
  session_id uuid,
  auth_roles kovcheg.auth_account_role[]
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT
    session.account_id,
    session.id,
    ARRAY[profile.auth_role]::kovcheg.auth_account_role[]
  FROM kovcheg.auth_sessions AS session
  JOIN kovcheg.account_auth_profiles AS profile
    ON profile.account_id = session.account_id
  JOIN kovcheg.accounts AS account
    ON account.id = session.account_id
  WHERE session.token_verifier = p_token_verifier
    AND session.revoked_at IS NULL
    AND p_now >= session.issued_at
    AND p_now < session.idle_expires_at
    AND p_now < session.absolute_expires_at
    AND account.status = 'active';
$$;

REVOKE ALL ON FUNCTION kovcheg.validate_auth_session(text, timestamptz) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION kovcheg.validate_auth_session(text, timestamptz)
TO kovcheg_auth_runtime;

LOCK TABLE
  kovcheg.auth_personal_gate_families,
  kovcheg.auth_personal_gate_sessions,
  kovcheg.auth_email_challenges,
  kovcheg.auth_sessions
IN ACCESS EXCLUSIVE MODE;

UPDATE kovcheg.auth_personal_gate_families AS family
SET status = 'revoked',
    revoked_at = GREATEST(pg_catalog.statement_timestamp(), family.issued_at),
    paused_until = NULL
WHERE family.status IN ('active', 'suspended');

UPDATE kovcheg.auth_personal_gate_sessions AS gate_session
SET revoked_at = GREATEST(pg_catalog.statement_timestamp(), gate_session.issued_at)
WHERE gate_session.revoked_at IS NULL;

UPDATE kovcheg.auth_email_challenges AS challenge
SET invalidated_at = GREATEST(pg_catalog.statement_timestamp(), challenge.issued_at)
WHERE challenge.gate_session_id IS NOT NULL
  AND challenge.used_at IS NULL
  AND challenge.invalidated_at IS NULL;

UPDATE kovcheg.auth_sessions AS application_session
SET revoked_at = GREATEST(
  pg_catalog.statement_timestamp(),
  application_session.issued_at
)
FROM kovcheg.auth_email_challenges AS challenge
WHERE application_session.source_challenge_id = challenge.id
  AND challenge.gate_session_id IS NOT NULL
  AND application_session.revoked_at IS NULL;

CREATE FUNCTION kovcheg.reject_retired_gate_session_source()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  IF NEW.source_challenge_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM kovcheg.auth_email_challenges AS challenge
      WHERE challenge.id = NEW.source_challenge_id
        AND challenge.gate_session_id IS NOT NULL
    )
  THEN
    RAISE EXCEPTION 'retired gate challenges cannot create application sessions'
      USING ERRCODE = '42501';
  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.reject_retired_gate_session_source() FROM PUBLIC;

CREATE TRIGGER auth_sessions_reject_retired_gate_source
BEFORE INSERT OR UPDATE OF source_challenge_id ON kovcheg.auth_sessions
FOR EACH ROW EXECUTE FUNCTION kovcheg.reject_retired_gate_session_source();

DROP TRIGGER accounts_revoke_personal_gate_on_deactivation
ON kovcheg.accounts;

CREATE FUNCTION kovcheg.revoke_auth_access_on_account_deactivation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  effective_time timestamptz;
BEGIN
  IF NEW.status <> 'active' AND OLD.status IS DISTINCT FROM NEW.status THEN
    effective_time := COALESCE(NEW.deactivated_at, pg_catalog.clock_timestamp());

    UPDATE kovcheg.auth_personal_gate_families AS family
    SET status = 'revoked',
        revoked_at = GREATEST(effective_time, family.issued_at),
        paused_until = NULL
    WHERE family.account_id = NEW.id
      AND family.status IN ('active', 'suspended');

    UPDATE kovcheg.auth_personal_gate_sessions AS gate_session
    SET revoked_at = GREATEST(effective_time, gate_session.issued_at)
    WHERE gate_session.account_id = NEW.id
      AND gate_session.revoked_at IS NULL;

    UPDATE kovcheg.auth_email_challenges AS challenge
    SET invalidated_at = GREATEST(effective_time, challenge.issued_at)
    WHERE challenge.account_id = NEW.id
      AND challenge.used_at IS NULL
      AND challenge.invalidated_at IS NULL;

    UPDATE kovcheg.auth_sessions AS application_session
    SET revoked_at = GREATEST(effective_time, application_session.issued_at)
    WHERE application_session.account_id = NEW.id
      AND application_session.revoked_at IS NULL;
  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.revoke_auth_access_on_account_deactivation()
FROM PUBLIC;

CREATE TRIGGER accounts_revoke_auth_access_on_deactivation
AFTER UPDATE OF status ON kovcheg.accounts
FOR EACH ROW EXECUTE FUNCTION kovcheg.revoke_auth_access_on_account_deactivation();

CREATE OR REPLACE FUNCTION kovcheg.admin_security_reset_auth_access(
  p_actor_session_verifier text,
  p_account_id uuid,
  p_now timestamptz,
  p_correlation_id varchar
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  actor_account_id uuid;
  revoked_family_count integer := 0;
  revoked_gate_session_count integer := 0;
  revoked_passkey_count integer := 0;
  invalidated_challenge_count integer := 0;
  revoked_application_session_count integer := 0;
  migration_version text;
  result jsonb;
BEGIN
  actor_account_id := kovcheg.require_active_auth_administrator(
    p_actor_session_verifier,
    p_now
  );

  PERFORM 1
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.account_id = p_account_id
  FOR UPDATE OF profile, account;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'auth account target not found' USING ERRCODE = 'P0002';
  END IF;

  UPDATE kovcheg.auth_personal_gate_families AS family
  SET status = 'revoked',
      revoked_at = GREATEST(p_now, family.issued_at),
      paused_until = NULL
  WHERE family.account_id = p_account_id
    AND family.status IN ('active', 'suspended');
  GET DIAGNOSTICS revoked_family_count = ROW_COUNT;

  UPDATE kovcheg.auth_personal_gate_sessions AS gate_session
  SET revoked_at = GREATEST(p_now, gate_session.issued_at)
  WHERE gate_session.account_id = p_account_id
    AND gate_session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_gate_session_count = ROW_COUNT;

  UPDATE kovcheg.auth_passkey_credentials AS passkey
  SET revoked_at = GREATEST(p_now, passkey.created_at)
  WHERE passkey.account_id = p_account_id
    AND passkey.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_passkey_count = ROW_COUNT;

  UPDATE kovcheg.auth_email_challenges AS challenge
  SET invalidated_at = GREATEST(p_now, challenge.issued_at)
  WHERE challenge.account_id = p_account_id
    AND challenge.used_at IS NULL
    AND challenge.invalidated_at IS NULL;
  GET DIAGNOSTICS invalidated_challenge_count = ROW_COUNT;

  UPDATE kovcheg.auth_sessions AS application_session
  SET revoked_at = GREATEST(p_now, application_session.issued_at)
  WHERE application_session.account_id = p_account_id
    AND application_session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_application_session_count = ROW_COUNT;

  result := pg_catalog.jsonb_build_object(
    'revokedFamilyCount', revoked_family_count,
    'revokedGateSessionCount', revoked_gate_session_count,
    'revokedPasskeyCount', revoked_passkey_count,
    'invalidatedChallengeCount', invalidated_challenge_count,
    'revokedApplicationSessionCount', revoked_application_session_count
  );

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    actor_account_id,
    'auth.access.security-reset',
    'auth_account',
    p_account_id,
    'success',
    pg_catalog.jsonb_build_object(
      'retiredGateFamilyCount', revoked_family_count,
      'retiredGateSessionCount', revoked_gate_session_count,
      'revokedPasskeyCount', revoked_passkey_count,
      'invalidatedChallengeCount', invalidated_challenge_count,
      'revokedApplicationSessionCount', revoked_application_session_count
    )
  );

  RETURN result;
END;
$$;

CREATE FUNCTION kovcheg.issue_auth_email_challenge(
  p_email text,
  p_challenge_id uuid,
  p_code_verifier text,
  p_issued_at timestamptz,
  p_expires_at timestamptz,
  p_max_attempts integer,
  p_resend_cooldown interval,
  p_correlation_id varchar
)
RETURNS TABLE (
  outcome varchar,
  challenge_id uuid,
  recipient varchar
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  normalized_email text := pg_catalog.lower(pg_catalog.btrim(p_email));
  matched_account_id uuid;
  matched_recipient varchar(254);
  latest_issued_at timestamptz;
  migration_version text;
BEGIN
  IF p_challenge_id IS NULL
    OR p_code_verifier IS NULL
    OR p_code_verifier !~ '^[A-Za-z0-9_-]{43}$'
    OR p_issued_at IS NULL
    OR p_expires_at IS NULL
    OR p_expires_at <= p_issued_at
    OR p_expires_at > p_issued_at + interval '10 minutes'
    OR p_max_attempts IS NULL
    OR p_max_attempts <> 5
    OR p_resend_cooldown IS NULL
    OR p_resend_cooldown < interval '60 seconds'
    OR p_correlation_id IS NULL
    OR p_correlation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  THEN
    RAISE EXCEPTION 'invalid email challenge input' USING ERRCODE = '23514';
  END IF;

  SELECT profile.account_id, profile.email
  INTO matched_account_id, matched_recipient
  FROM kovcheg.account_auth_profiles AS profile
  JOIN kovcheg.accounts AS account ON account.id = profile.account_id
  WHERE profile.email = normalized_email
    AND account.status = 'active'
  FOR UPDATE OF profile, account;

  IF NOT FOUND THEN
    outcome := 'neutral';
    RETURN NEXT;
    RETURN;
  END IF;

  SELECT challenge.issued_at
  INTO latest_issued_at
  FROM kovcheg.auth_email_challenges AS challenge
  WHERE challenge.account_id = matched_account_id
    AND challenge.gate_session_id IS NULL
  ORDER BY challenge.issued_at DESC
  LIMIT 1;

  IF latest_issued_at IS NOT NULL
    AND p_issued_at - latest_issued_at < p_resend_cooldown
  THEN
    outcome := 'neutral';
    RETURN NEXT;
    RETURN;
  END IF;

  UPDATE kovcheg.auth_email_challenges AS challenge
  SET invalidated_at = GREATEST(p_issued_at, challenge.issued_at)
  WHERE challenge.account_id = matched_account_id
    AND challenge.used_at IS NULL
    AND challenge.invalidated_at IS NULL;

  INSERT INTO kovcheg.auth_email_challenges (
    id,
    account_id,
    code_verifier,
    issued_at,
    expires_at,
    max_attempts,
    gate_session_id
  ) VALUES (
    p_challenge_id,
    matched_account_id,
    p_code_verifier,
    p_issued_at,
    p_expires_at,
    p_max_attempts,
    NULL
  );

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  PERFORM kovcheg.append_audit_event(
    p_correlation_id,
    migration_version::varchar,
    NULL,
    'auth.email-challenge.issued',
    'auth_account',
    matched_account_id,
    'success',
    '{}'::jsonb
  );

  outcome := 'issued';
  challenge_id := p_challenge_id;
  recipient := matched_recipient;
  RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION kovcheg.issue_auth_email_challenge(
  text, uuid, text, timestamptz, timestamptz, integer, interval, varchar
) IS
  'Trusted Variant E email challenge issuance for a pre-created active account. The caller must keep the external response neutral and must never persist or log the raw one-time code.';

COMMENT ON TABLE kovcheg.auth_personal_gate_families IS
  'Retired personal-entry-gate evidence. Variant E runtime has no EXECUTE or direct DML access.';
COMMENT ON TABLE kovcheg.auth_personal_gate_sessions IS
  'Retired personal-entry-gate session evidence. Records cannot authorize or extend access.';
COMMENT ON FUNCTION kovcheg.revoke_auth_personal_gate_on_account_deactivation() IS
  'Retired implementation retained as migration history. No trigger invokes this function after Variant E.';
COMMENT ON FUNCTION kovcheg.revoke_auth_access_on_account_deactivation() IS
  'Fail-closed account deactivation boundary for challenges and application sessions; retired gate evidence is also terminalized.';

REVOKE EXECUTE ON FUNCTION kovcheg.issue_auth_challenge_for_active_account(
  text, uuid, text, timestamptz, timestamptz, integer, interval
) FROM kovcheg_auth_runtime, kovcheg_auth_app;
REVOKE EXECUTE ON FUNCTION kovcheg.admin_issue_auth_personal_gate(
  text, uuid, uuid, text, timestamptz, varchar
) FROM kovcheg_auth_runtime, kovcheg_auth_app;
REVOKE EXECUTE ON FUNCTION kovcheg.admin_reissue_auth_personal_gate(
  text, uuid, uuid, text, timestamptz, varchar
) FROM kovcheg_auth_runtime, kovcheg_auth_app;
REVOKE EXECUTE ON FUNCTION kovcheg.admin_revoke_auth_personal_gate(
  text, uuid, uuid, timestamptz, varchar
) FROM kovcheg_auth_runtime, kovcheg_auth_app;
REVOKE EXECUTE ON FUNCTION kovcheg.admin_resume_auth_personal_gate(
  text, uuid, uuid, timestamptz, varchar
) FROM kovcheg_auth_runtime, kovcheg_auth_app;
REVOKE EXECUTE ON FUNCTION kovcheg.activate_auth_personal_gate(
  text, uuid, text, text, timestamptz, varchar
) FROM kovcheg_auth_runtime, kovcheg_auth_app;
REVOKE EXECUTE ON FUNCTION kovcheg.validate_auth_personal_gate_session(
  text, timestamptz
) FROM kovcheg_auth_runtime, kovcheg_auth_app;
REVOKE EXECUTE ON FUNCTION kovcheg.issue_auth_challenge_for_personal_gate(
  text, text, uuid, text, timestamptz, timestamptz, integer, interval, varchar
) FROM kovcheg_auth_runtime, kovcheg_auth_app;
REVOKE EXECUTE ON FUNCTION kovcheg.extend_auth_personal_gate_after_login(
  text, text, timestamptz
) FROM kovcheg_auth_runtime, kovcheg_auth_app;

REVOKE ALL ON FUNCTION kovcheg.issue_auth_email_challenge(
  text, uuid, text, timestamptz, timestamptz, integer, interval, varchar
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION kovcheg.issue_auth_email_challenge(
  text, uuid, text, timestamptz, timestamptz, integer, interval, varchar
) TO kovcheg_auth_runtime;

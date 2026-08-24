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

SELECT pg_temp.assert_true(
  kovcheg.current_migration_version() = '0008'
  AND (SELECT count(*) = 8 FROM kovcheg_meta.schema_migrations),
  'the eight-migration persona data-owner boundary must be recorded'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.account_auth_profiles AS profile
    JOIN kovcheg.accounts AS account ON account.id = profile.account_id
    WHERE account.kind <> 'person'
  ),
  'auth profiles must belong only to person accounts'
);

DO $$
BEGIN
  BEGIN
    INSERT INTO kovcheg.account_auth_profiles (
      account_id,
      email,
      display_name,
      auth_role
    ) VALUES (
      '00000000-0000-4000-8000-000000001001',
      'system-persona@identity.invalid',
      'System Persona',
      'student'
    );
    RAISE EXCEPTION 'a system persona received an auth profile';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO kovcheg.auth_email_challenges (
      id,
      account_id,
      code_verifier,
      issued_at,
      expires_at,
      max_attempts
    ) VALUES (
      '00000000-0000-4000-8000-000000008101',
      '00000000-0000-4000-8000-000000001001',
      repeat('a', 43),
      '2030-01-01 01:00:00+00',
      '2030-01-01 01:10:00+00',
      5
    );
    RAISE EXCEPTION 'a system persona received an email challenge';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO kovcheg.auth_sessions (
      id,
      account_id,
      token_verifier,
      issued_at,
      last_seen_at,
      idle_lifetime_ms,
      idle_expires_at,
      absolute_expires_at
    ) VALUES (
      '00000000-0000-4000-8000-000000008201',
      '00000000-0000-4000-8000-000000001001',
      repeat('b', 43),
      '2030-01-01 01:00:00+00',
      '2030-01-01 01:00:00+00',
      60000,
      '2030-01-01 01:01:00+00',
      '2030-01-01 02:00:00+00'
    );
    RAISE EXCEPTION 'a system persona received an application session';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_email_challenges
    WHERE account_id = '00000000-0000-4000-8000-000000001001'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.auth_sessions
    WHERE account_id = '00000000-0000-4000-8000-000000001001'
  ),
  'rejected system persona auth state must leave no rows'
);

DO $$
BEGIN
  BEGIN
    UPDATE kovcheg.accounts
    SET kind = 'synthetic_system'
    WHERE id = '00000000-0000-4000-8000-000000003002';
    RAISE EXCEPTION 'an account with auth state became a system persona';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT kind = 'person'
    FROM kovcheg.accounts
    WHERE id = '00000000-0000-4000-8000-000000003002'
  ),
  'an account with an auth profile must remain a person account'
);

DO $$
BEGIN
  BEGIN
    INSERT INTO kovcheg.system_persona_operator_grants (
      operator_account_id,
      persona_account_id,
      status,
      granted_at,
      granted_by_account_id,
      updated_at
    ) VALUES (
      '00000000-0000-4000-8000-000000001002',
      '00000000-0000-4000-8000-000000001001',
      'active',
      '2030-01-01 01:00:00+00',
      '00000000-0000-4000-8000-000000003001',
      '2030-01-01 01:00:00+00'
    );
    RAISE EXCEPTION 'a system account became an operator';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    INSERT INTO kovcheg.system_persona_operator_grants (
      operator_account_id,
      persona_account_id,
      status,
      granted_at,
      granted_by_account_id,
      updated_at
    ) VALUES (
      '00000000-0000-4000-8000-000000003002',
      '00000000-0000-4000-8000-000000003003',
      'active',
      '2030-01-01 01:00:00+00',
      '00000000-0000-4000-8000-000000003001',
      '2030-01-01 01:00:00+00'
    );
    RAISE EXCEPTION 'a person account became a system persona';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT status = 'revoked'
      AND granted_by_account_id = '00000000-0000-4000-8000-000000003001'
      AND revoked_by_account_id = '00000000-0000-4000-8000-000000003001'
      AND granted_at = '2030-01-01 00:21:00+00'
      AND revoked_at = '2030-01-01 00:21:02+00'
    FROM kovcheg.system_persona_operator_grants
    WHERE operator_account_id = '00000000-0000-4000-8000-000000003002'
      AND persona_account_id = '00000000-0000-4000-8000-000000001001'
  ),
  'one operator grant must be revoked independently with complete attribution'
);

SELECT pg_temp.assert_true(
  (
    SELECT status = 'active'
      AND revoked_at IS NULL
      AND revoked_by_account_id IS NULL
    FROM kovcheg.system_persona_operator_grants
    WHERE operator_account_id = '00000000-0000-4000-8000-000000003003'
      AND persona_account_id = '00000000-0000-4000-8000-000000001001'
  ),
  'revoking one operator must leave another operator grant active'
);

SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 3
    FROM kovcheg.audit_events AS event
    WHERE event.correlation_id IN (
      'persona-grant-operator-one',
      'persona-grant-operator-two',
      'persona-revoke-operator-one'
    )
      AND event.actor_account_id = '00000000-0000-4000-8000-000000003001'
      AND event.target_type = 'system_persona'
      AND event.target_id = '00000000-0000-4000-8000-000000001001'
      AND event.outcome = 'success'
      AND event.details ? 'operatorAccountId'
  ),
  'grant and revoke audit must attribute the personal actor and target persona'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.audit_events AS event
    WHERE event.correlation_id IN (
      'persona-grant-failed-student',
      'persona-grant-failed-duplicate',
      'persona-revoke-failed-student',
      'persona-revoke-missing-retry'
    )
  ),
  'rejected or ineffective operator changes must append no audit event'
);

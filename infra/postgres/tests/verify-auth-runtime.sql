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
  NOT has_table_privilege(
    current_user,
    'kovcheg.account_auth_profiles',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    current_user,
    'kovcheg.auth_email_challenges',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    current_user,
    'kovcheg.auth_sessions',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    current_user,
    'kovcheg.oidc_provider_artifacts',
    'SELECT,INSERT,UPDATE,DELETE'
  ),
  'the auth login must not receive direct table DML'
);

SELECT pg_temp.assert_true(
  has_function_privilege(
    current_user,
    'kovcheg.bootstrap_auth_administrator(text,uuid,text,text)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    current_user,
    'kovcheg.provision_account_with_starter_set(uuid,character varying)',
    'EXECUTE'
  ),
  'the auth login must use only its narrow protected functions'
);

SELECT pg_temp.assert_true(
  (
    SELECT created
      AND account_id = '00000000-0000-4000-8000-000000003001'
      AND auth_role = 'administrator'
      AND account_status = 'active'
    FROM kovcheg.bootstrap_auth_administrator(
      'synthetic-bootstrap-0001',
      '00000000-0000-4000-8000-000000003001',
      'synthetic-administrator@auth.invalid',
      'Synthetic Administrator'
    )
  ),
  'administrator bootstrap must create one active administrator account'
);

SELECT pg_temp.assert_true(
  (
    SELECT NOT created
      AND account_id = '00000000-0000-4000-8000-000000003001'
      AND display_name = 'Synthetic Administrator'
    FROM kovcheg.bootstrap_auth_administrator(
      'synthetic-bootstrap-0001',
      '00000000-0000-4000-8000-000000003001',
      'synthetic-administrator@auth.invalid',
      'Ignored Retry Name'
    )
  ),
  'the same bootstrap binding must return the original account idempotently'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.bootstrap_auth_administrator(
      'synthetic-bootstrap-0001',
      '00000000-0000-4000-8000-000000003099',
      'synthetic-conflict@auth.invalid',
      'Synthetic Conflict'
    );
    RAISE EXCEPTION 'a conflicting bootstrap binding was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000003002'
      AND email = 'synthetic-student@auth.invalid'
      AND auth_role = 'student'
      AND account_status = 'active'
    FROM kovcheg.create_auth_account(
      '00000000-0000-4000-8000-000000003002',
      'Synthetic-Student@Auth.Invalid',
      'Synthetic Student'
    )
  ),
  'account creation must normalize email and provision one active student atomically'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.create_auth_account(
      '00000000-0000-4000-8000-000000003098',
      repeat('x', 250) || '@auth.invalid',
      'Synthetic Overlong Contact'
    );
    RAISE EXCEPTION 'an overlong contact value was silently truncated';
  EXCEPTION WHEN string_data_right_truncation THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.find_auth_account_by_id(
      '00000000-0000-4000-8000-000000003098'
    )
  ),
  'failed auth profile creation must roll back the canonical account and starter set'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'neutral'
      AND account_id IS NULL
      AND challenge_id IS NULL
      AND recipient IS NULL
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-unknown@auth.invalid',
      '00000000-0000-4000-8000-000000003101',
      repeat('u', 43),
      '2030-01-01 00:00:00+00',
      '2030-01-01 00:10:00+00',
      5,
      interval '60 seconds'
    )
  ),
  'unknown accounts must receive the neutral result without identity disclosure'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
      AND account_id = '00000000-0000-4000-8000-000000003002'
      AND challenge_id = '00000000-0000-4000-8000-000000003102'
      AND recipient = 'synthetic-student@auth.invalid'
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-student@auth.invalid',
      '00000000-0000-4000-8000-000000003102',
      repeat('a', 43),
      '2030-01-01 00:00:00+00',
      '2030-01-01 00:10:00+00',
      5,
      interval '60 seconds'
    )
  ),
  'an active account must receive one durable HMAC challenge verifier'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'neutral'
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-student@auth.invalid',
      '00000000-0000-4000-8000-000000003103',
      repeat('b', 43),
      '2030-01-01 00:00:30+00',
      '2030-01-01 00:10:30+00',
      5,
      interval '60 seconds'
    )
  ),
  'the resend cooldown must return the same neutral result without a new challenge'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-student@auth.invalid',
      '00000000-0000-4000-8000-000000003104',
      repeat('c', 43),
      '2030-01-01 00:01:01+00',
      '2030-01-01 00:11:01+00',
      5,
      interval '60 seconds'
    )
  ),
  'a later challenge must invalidate the previous open challenge atomically'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'invalid'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003102',
      repeat('a', 43),
      '2030-01-01 00:01:02+00',
      '00000000-0000-4000-8000-000000003201',
      repeat('s', 43),
      '2030-01-01 00:01:02+00',
      60000,
      '2030-01-01 00:11:02+00'
    )
  ),
  'an invalidated earlier challenge must not create a session'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'invalid'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003104',
      repeat('z', 43),
      '2030-01-01 00:01:03+00',
      '00000000-0000-4000-8000-000000003202',
      repeat('t', 43),
      '2030-01-01 00:01:03+00',
      60000,
      '2030-01-01 00:11:03+00'
    )
  ),
  'a mismatched verifier must increment attempts without creating a session'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'authenticated'
      AND account_id = '00000000-0000-4000-8000-000000003002'
      AND session_id = '00000000-0000-4000-8000-000000003203'
      AND auth_roles = ARRAY['student'::kovcheg.auth_account_role]
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003104',
      repeat('c', 43),
      '2030-01-01 00:01:04+00',
      '00000000-0000-4000-8000-000000003203',
      repeat('v', 43),
      '2030-01-01 00:01:04+00',
      60000,
      '2030-01-01 00:11:04+00'
    )
  ),
  'a matching verifier must consume once and create the session in one transaction'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000003002'
      AND session_id = '00000000-0000-4000-8000-000000003203'
    FROM kovcheg.authenticate_auth_session(
      repeat('v', 43),
      '2030-01-01 00:01:30+00'
    )
  ),
  'session authentication must recheck account state and extend idle expiry'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'invalid'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003104',
      repeat('c', 43),
      '2030-01-01 00:01:31+00',
      '00000000-0000-4000-8000-000000003204',
      repeat('w', 43),
      '2030-01-01 00:01:31+00',
      60000,
      '2030-01-01 00:11:31+00'
    )
  ),
  'a consumed challenge must reject replay'
);

SELECT pg_temp.assert_true(
  kovcheg.revoke_auth_session_by_id(
    '00000000-0000-4000-8000-000000003203',
    '2030-01-01 00:01:32+00'
  )
  AND NOT kovcheg.revoke_auth_session_by_id(
    '00000000-0000-4000-8000-000000003203',
    '2030-01-01 00:01:33+00'
  ),
  'session revocation by ID must retain not-found and idempotent semantics'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM kovcheg.authenticate_auth_session(
      repeat('v', 43),
      '2030-01-01 00:01:34+00'
    )
  ),
  'a revoked session must not authenticate'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-student@auth.invalid',
      '00000000-0000-4000-8000-000000003105',
      repeat('d', 43),
      '2030-01-01 00:03:00+00',
      '2030-01-01 00:13:00+00',
      5,
      interval '60 seconds'
    )
  ),
  'a later active-account challenge must be issuable'
);

SELECT kovcheg.invalidate_auth_challenge(
  '00000000-0000-4000-8000-000000003105',
  '2030-01-01 00:03:01+00'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'invalid'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003105',
      repeat('d', 43),
      '2030-01-01 00:03:02+00',
      '00000000-0000-4000-8000-000000003205',
      repeat('x', 43),
      '2030-01-01 00:03:02+00',
      60000,
      '2030-01-01 00:13:02+00'
    )
  ),
  'explicit challenge invalidation must prevent later use'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-student@auth.invalid',
      '00000000-0000-4000-8000-000000003106',
      repeat('e', 43),
      '2030-01-01 00:05:00+00',
      '2030-01-01 00:15:00+00',
      5,
      interval '60 seconds'
    )
  ),
  'a challenge must be available for account deactivation testing'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003106',
      repeat('e', 43),
      '2030-01-01 00:05:01+00',
      '00000000-0000-4000-8000-000000003206',
      repeat('y', 43),
      '2030-01-01 00:05:01+00',
      60000,
      '2030-01-01 00:15:01+00'
    )
  ),
  'a second valid session must be created before account deactivation'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-student@auth.invalid',
      '00000000-0000-4000-8000-000000003107',
      repeat('f', 43),
      '2030-01-01 00:07:00+00',
      '2030-01-01 00:17:00+00',
      5,
      interval '60 seconds'
    )
  ),
  'one live challenge must exist before the atomic account-status transition'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_status = 'deactivated'
    FROM kovcheg.set_auth_account_status_and_revoke(
      '00000000-0000-4000-8000-000000003002',
      'deactivated',
      '2030-01-01 00:07:01+00'
    )
  ),
  'deactivation must update the canonical account state'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM kovcheg.authenticate_auth_session(
      repeat('y', 43),
      '2030-01-01 00:07:02+00'
    )
  )
  AND (
    SELECT outcome = 'neutral'
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-student@auth.invalid',
      '00000000-0000-4000-8000-000000003108',
      repeat('g', 43),
      '2030-01-01 00:08:30+00',
      '2030-01-01 00:18:30+00',
      5,
      interval '60 seconds'
    )
  )
  AND (
    SELECT outcome = 'invalid'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003107',
      repeat('f', 43),
      '2030-01-01 00:08:31+00',
      '00000000-0000-4000-8000-000000003207',
      repeat('h', 43),
      '2030-01-01 00:08:31+00',
      60000,
      '2030-01-01 00:18:31+00'
    )
  ),
  'deactivation must revoke every live session and challenge atomically'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_status = 'active'
    FROM kovcheg.set_auth_account_status_and_revoke(
      '00000000-0000-4000-8000-000000003002',
      'active',
      '2030-01-01 00:09:00+00'
    )
  ),
  'reactivation must preserve the auth profile without restoring revoked state'
);

SELECT kovcheg.upsert_oidc_provider_artifact(
  'AuthorizationCode',
  'synthetic-artifact-0001',
  '{"fixture":"synthetic","grantId":"synthetic-grant-0001"}'::jsonb,
  '2030-01-01 01:00:00+00',
  'synthetic-grant-0001',
  'synthetic-user-code-0001',
  'synthetic-uid-0001'
);

SELECT pg_temp.assert_true(
  (
    SELECT payload ->> 'fixture' = 'synthetic' AND consumed_at IS NULL
    FROM kovcheg.find_oidc_provider_artifact(
      'AuthorizationCode',
      'synthetic-artifact-0001',
      '2030-01-01 00:10:00+00'
    )
  )
  AND (
    SELECT artifact_id = 'synthetic-artifact-0001'
    FROM kovcheg.find_oidc_provider_artifact_by_user_code(
      'synthetic-user-code-0001',
      '2030-01-01 00:10:00+00'
    )
  )
  AND (
    SELECT artifact_id = 'synthetic-artifact-0001'
    FROM kovcheg.find_oidc_provider_artifact_by_uid(
      'synthetic-uid-0001',
      '2030-01-01 00:10:00+00'
    )
  ),
  'the OIDC adapter must find durable unexpired artifacts through each lookup key'
);

SELECT pg_temp.assert_true(
  kovcheg.consume_oidc_provider_artifact(
    'AuthorizationCode',
    'synthetic-artifact-0001',
    '2030-01-01 00:10:01+00'
  )
  AND NOT kovcheg.consume_oidc_provider_artifact(
    'AuthorizationCode',
    'synthetic-artifact-0001',
    '2030-01-01 00:10:02+00'
  ),
  'OIDC consume state must reject a replay atomically'
);

SELECT kovcheg.upsert_oidc_provider_artifact(
  'AuthorizationCode',
  'synthetic-artifact-0001',
  '{"fixture":"updated","grantId":"synthetic-grant-0001"}'::jsonb,
  '2030-01-01 01:00:00+00',
  'synthetic-grant-0001',
  'synthetic-user-code-0001',
  'synthetic-uid-0001'
);

SELECT pg_temp.assert_true(
  (
    SELECT consumed_at = '2030-01-01 00:10:01+00'::timestamptz
    FROM kovcheg.find_oidc_provider_artifact(
      'AuthorizationCode',
      'synthetic-artifact-0001',
      '2030-01-01 00:10:03+00'
    )
  ),
  'an adapter upsert must never reset durable consume state'
);

SELECT pg_temp.assert_true(
  kovcheg.revoke_oidc_provider_artifacts_by_grant_id('synthetic-grant-0001') = 1,
  'grant revocation must report every destroyed OIDC adapter artifact'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.find_oidc_provider_artifact(
      'AuthorizationCode',
      'synthetic-artifact-0001',
      '2030-01-01 00:10:04+00'
    )
  ),
  'grant revocation must make every matching OIDC adapter artifact unavailable'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-student@auth.invalid',
      '00000000-0000-4000-8000-000000003109',
      repeat('k', 43),
      '2030-01-01 00:20:00+00',
      '2030-01-01 00:30:00+00',
      5,
      interval '60 seconds'
    )
  ),
  'the concurrent verification fixture must have one live challenge'
);

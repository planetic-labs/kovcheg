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
  )
  AND NOT has_table_privilege(
    current_user,
    'kovcheg.system_persona_operator_grants',
    'SELECT,INSERT,UPDATE,DELETE'
  ),
  'the auth login must not receive direct table DML'
);

SELECT pg_temp.assert_true(
  has_function_privilege(
    current_user,
    'kovcheg.bootstrap_role_capable_administrator(text,uuid,text,text)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.admin_create_role_capable_account(text,uuid,text,text,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.admin_update_auth_account(text,uuid,text,text,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.admin_set_auth_account_status(text,uuid,kovcheg.account_status,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.admin_revoke_auth_session(text,uuid,uuid,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.admin_revoke_all_auth_sessions(text,uuid,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.validate_auth_session(text,timestamp with time zone)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.admin_grant_system_persona_operator(text,uuid,uuid,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.admin_revoke_system_persona_operator(text,uuid,uuid,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    current_user,
    'kovcheg.create_auth_account(uuid,text,text)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    current_user,
    'kovcheg.set_auth_account_status_and_revoke(uuid,kovcheg.account_status,timestamp with time zone)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    current_user,
    'kovcheg.revoke_auth_session_by_id(uuid,timestamp with time zone)',
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
      AND account_access = 'member'
      AND account_status = 'active'
      AND domain_status = 'incubator_participant'
      AND functional_grants @> ARRAY['platform_administrator']
    FROM kovcheg.bootstrap_role_capable_administrator(
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
    FROM kovcheg.bootstrap_role_capable_administrator(
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
    FROM kovcheg.bootstrap_role_capable_administrator(
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
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-administrator@auth.invalid',
      '00000000-0000-4000-8000-000000003090',
      repeat('i', 43),
      '2029-12-31 23:50:00+00',
      '2030-01-01 00:00:00+00',
      5,
      interval '60 seconds',
      'auth-email-3090'
    )
  ),
  'the bootstrap administrator must receive a challenge for an acting session'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'authenticated'
      AND account_id = '00000000-0000-4000-8000-000000003001'
      AND auth_roles = ARRAY['administrator'::kovcheg.auth_account_role]
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003090',
      repeat('i', 43),
      '2029-12-31 23:50:01+00',
      '00000000-0000-4000-8000-000000003091',
      repeat('m', 43),
      '2029-12-31 23:50:01+00',
      86400000,
      '2030-01-02 00:00:00+00'
    )
  ),
  'the administrator challenge must create one current acting session'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000003002'
      AND email = 'synthetic-member@auth.invalid'
      AND account_access = 'member'
      AND account_status = 'active'
      AND domain_status = 'incubator_participant'
      AND functional_grants = ARRAY[]::text[]
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003002',
      'Synthetic-Member@Auth.Invalid',
      'Synthetic Member',
      '2030-01-01 00:00:00+00',
      'auth-admin-create-001'
    )
  ),
  'authorized account creation must normalize and provision one active member atomically'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003098',
      repeat('x', 250) || '@auth.invalid',
      'Synthetic Overlong Contact',
      '2030-01-01 00:00:01+00',
      'auth-admin-failed-overlong'
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
    SELECT email = 'synthetic-member@auth.invalid'
      AND display_name = 'Synthetic Member Updated'
    FROM kovcheg.admin_update_auth_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003002',
      'Synthetic-Member@Auth.Invalid',
      '  Synthetic Member Updated  ',
      '2030-01-01 00:00:02+00',
      'auth-admin-update-001'
    )
  ),
  'authorized profile updates must normalize email and display name'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000003003'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003003',
      'synthetic-secondary@auth.invalid',
      'Synthetic Secondary',
      '2030-01-01 00:00:03+00',
      'auth-admin-create-secondary'
    )
  ),
  'the administrator must be able to create a second isolated target account'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.admin_update_auth_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003003',
      'synthetic-member@auth.invalid',
      'Must Roll Back',
      '2030-01-01 00:00:04+00',
      'auth-admin-failed-update-conflict'
    );
    RAISE EXCEPTION 'a conflicting normalized email update was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT email = 'synthetic-secondary@auth.invalid'
      AND display_name = 'Synthetic Secondary'
    FROM kovcheg.find_auth_account_by_id(
      '00000000-0000-4000-8000-000000003003'
    )
  ),
  'a conflicting profile update must roll back every field and its audit event'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.admin_update_auth_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003003',
      'synthetic-rollback@auth.invalid',
      'Must Also Roll Back',
      '2030-01-01 00:00:05+00',
      'invalid correlation id'
    );
    RAISE EXCEPTION 'an invalid audit correlation ID was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT email = 'synthetic-secondary@auth.invalid'
      AND display_name = 'Synthetic Secondary'
    FROM kovcheg.find_auth_account_by_id(
      '00000000-0000-4000-8000-000000003003'
    )
  ),
  'an audit insert failure must roll back the protected profile mutation'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'neutral'
      AND challenge_id IS NULL
      AND recipient IS NULL
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-unknown@auth.invalid',
      '00000000-0000-4000-8000-000000003101',
      repeat('u', 43),
      '2030-01-01 00:00:00+00',
      '2030-01-01 00:10:00+00',
      5,
      interval '60 seconds',
      'auth-email-3101-neutral'
    )
  ),
  'unknown accounts must receive the neutral result without identity disclosure'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
      AND challenge_id = '00000000-0000-4000-8000-000000003102'
      AND recipient = 'synthetic-member@auth.invalid'
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-member@auth.invalid',
      '00000000-0000-4000-8000-000000003102',
      repeat('a', 43),
      '2030-01-01 00:00:00+00',
      '2030-01-01 00:10:00+00',
      5,
      interval '60 seconds',
      'auth-email-3102'
    )
  ),
  'an active account must receive one durable HMAC challenge verifier'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'neutral'
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-member@auth.invalid',
      '00000000-0000-4000-8000-000000003103',
      repeat('b', 43),
      '2030-01-01 00:00:30+00',
      '2030-01-01 00:10:30+00',
      5,
      interval '60 seconds',
      'auth-email-3103-cooldown'
    )
  ),
  'the resend cooldown must return the same neutral result without a new challenge'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-member@auth.invalid',
      '00000000-0000-4000-8000-000000003104',
      repeat('c', 43),
      '2030-01-01 00:01:01+00',
      '2030-01-01 00:11:01+00',
      5,
      interval '60 seconds',
      'auth-email-3104'
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
      AND cardinality(auth_roles) = 1
      AND auth_roles[1] <> 'administrator'
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
  kovcheg.admin_revoke_auth_session(
    repeat('m', 43),
    '00000000-0000-4000-8000-000000003002',
    '00000000-0000-4000-8000-000000003203',
    '2030-01-01 00:01:32+00',
    'auth-admin-revoke-one-001'
  )
  AND NOT kovcheg.admin_revoke_auth_session(
    repeat('m', 43),
    '00000000-0000-4000-8000-000000003002',
    '00000000-0000-4000-8000-000000003203',
    '2030-01-01 00:01:33+00',
    'auth-admin-revoke-one-retry'
  ),
  'administrative session revocation must retain safe idempotent semantics'
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
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-member@auth.invalid',
      '00000000-0000-4000-8000-000000003105',
      repeat('d', 43),
      '2030-01-01 00:03:00+00',
      '2030-01-01 00:13:00+00',
      5,
      interval '60 seconds',
      'auth-email-3105'
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
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-member@auth.invalid',
      '00000000-0000-4000-8000-000000003106',
      repeat('e', 43),
      '2030-01-01 00:05:00+00',
      '2030-01-01 00:15:00+00',
      5,
      interval '60 seconds',
      'auth-email-3106'
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
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-member@auth.invalid',
      '00000000-0000-4000-8000-000000003107',
      repeat('f', 43),
      '2030-01-01 00:07:00+00',
      '2030-01-01 00:17:00+00',
      5,
      interval '60 seconds',
      'auth-email-3107'
    )
  ),
  'one live challenge must exist before the atomic account-status transition'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_status = 'deactivated'
    FROM kovcheg.admin_set_auth_account_status(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003002',
      'deactivated',
      '2030-01-01 00:07:01+00',
      'auth-admin-status-deactivated'
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
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-member@auth.invalid',
      '00000000-0000-4000-8000-000000003108',
      repeat('g', 43),
      '2030-01-01 00:08:30+00',
      '2030-01-01 00:18:30+00',
      5,
      interval '60 seconds',
      'auth-email-3108-deactivated'
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
    FROM kovcheg.admin_set_auth_account_status(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003002',
      'active',
      '2030-01-01 00:09:00+00',
      'auth-admin-status-active'
    )
  ),
  'reactivation must preserve the auth profile without restoring revoked state'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM kovcheg.authenticate_auth_session(
      repeat('y', 43),
      '2030-01-01 00:09:01+00'
    )
  ),
  'activation must not restore or create an application session'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-secondary@auth.invalid',
      '00000000-0000-4000-8000-000000003120',
      repeat('l', 43),
      '2030-01-01 00:09:10+00',
      '2030-01-01 00:19:10+00',
      5,
      interval '60 seconds',
      'auth-email-3120'
    )
  ),
  'the second target account must receive a challenge'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003120',
      repeat('l', 43),
      '2030-01-01 00:09:11+00',
      '00000000-0000-4000-8000-000000003220',
      repeat('n', 43),
      '2030-01-01 00:09:11+00',
      2400000,
      '2030-01-01 00:49:11+00'
    )
  ),
  'the second target account must have one isolated live session'
);

SELECT pg_temp.assert_true(
  NOT kovcheg.admin_revoke_auth_session(
    repeat('m', 43),
    '00000000-0000-4000-8000-000000003002',
    '00000000-0000-4000-8000-000000003220',
    '2030-01-01 00:09:12+00',
    'auth-admin-revoke-cross-owner'
  )
  AND (
    SELECT session_id = '00000000-0000-4000-8000-000000003220'
    FROM kovcheg.authenticate_auth_session(
      repeat('n', 43),
      '2030-01-01 00:09:13+00'
    )
  ),
  'one-session revocation must not affect a session owned by another account'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-member@auth.invalid',
      '00000000-0000-4000-8000-000000003121',
      repeat('o', 43),
      '2030-01-01 00:10:00+00',
      '2030-01-01 00:20:00+00',
      5,
      interval '60 seconds',
      'auth-email-3121'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003121',
      repeat('o', 43),
      '2030-01-01 00:10:01+00',
      '00000000-0000-4000-8000-000000003221',
      repeat('o', 43),
      '2030-01-01 00:10:01+00',
      1800000,
      '2030-01-01 00:40:01+00'
    )
  ),
  'the ordinary account authorization-negative fixture must have a current session'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.admin_update_auth_account(
      repeat('o', 43),
      '00000000-0000-4000-8000-000000003003',
      'synthetic-secondary@auth.invalid',
      'Unauthorized Member Update',
      '2030-01-01 00:10:02+00',
      'auth-admin-failed-ordinary'
    );
    RAISE EXCEPTION 'an ordinary session performed an administrative update';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT display_name = 'Synthetic Secondary'
    FROM kovcheg.find_auth_account_by_id(
      '00000000-0000-4000-8000-000000003003'
    )
  ),
  'an ordinary acting session must fail without mutating the target account'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-administrator@auth.invalid',
      '00000000-0000-4000-8000-000000003122',
      repeat('p', 43),
      '2030-01-01 00:11:00+00',
      '2030-01-01 00:11:10+00',
      5,
      interval '60 seconds',
      'auth-email-3122'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003122',
      repeat('p', 43),
      '2030-01-01 00:11:01+00',
      '00000000-0000-4000-8000-000000003222',
      repeat('p', 43),
      '2030-01-01 00:11:01+00',
      1000,
      '2030-01-01 00:11:02+00'
    )
  ),
  'the expired administrator-session fixture must be created before expiry'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.admin_create_role_capable_account(
      repeat('p', 43),
      '00000000-0000-4000-8000-000000003096',
      'synthetic-expired-actor@auth.invalid',
      'Expired Actor Attempt',
      '2030-01-01 00:11:03+00',
      'auth-admin-failed-expired'
    );
    RAISE EXCEPTION 'an expired administrator session created an account';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM kovcheg.find_auth_account_by_id(
      '00000000-0000-4000-8000-000000003096'
    )
  ),
  'an expired acting session must fail without provisioning an account'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-administrator@auth.invalid',
      '00000000-0000-4000-8000-000000003123',
      repeat('q', 43),
      '2030-01-01 00:12:00+00',
      '2030-01-01 00:22:00+00',
      5,
      interval '60 seconds',
      'auth-email-3123'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003123',
      repeat('q', 43),
      '2030-01-01 00:12:01+00',
      '00000000-0000-4000-8000-000000003223',
      repeat('r', 43),
      '2030-01-01 00:12:01+00',
      1080000,
      '2030-01-01 00:30:01+00'
    )
  )
  AND kovcheg.revoke_auth_session_by_verifier(
    repeat('r', 43),
    '2030-01-01 00:12:02+00'
  ),
  'the revoked administrator-session fixture must be explicitly revoked'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.admin_set_auth_account_status(
      repeat('r', 43),
      '00000000-0000-4000-8000-000000003003',
      'deactivated',
      '2030-01-01 00:12:03+00',
      'auth-admin-failed-revoked'
    );
    RAISE EXCEPTION 'a revoked administrator session changed account status';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM kovcheg.admin_revoke_all_auth_sessions(
      repeat('z', 43),
      '00000000-0000-4000-8000-000000003003',
      '2030-01-01 00:12:04+00',
      'auth-admin-failed-missing'
    );
    RAISE EXCEPTION 'a missing administrator session revoked target sessions';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT account_status = 'active'
    FROM kovcheg.find_auth_account_by_id(
      '00000000-0000-4000-8000-000000003003'
    )
  )
  AND (
    SELECT session_id = '00000000-0000-4000-8000-000000003220'
    FROM kovcheg.authenticate_auth_session(
      repeat('n', 43),
      '2030-01-01 00:12:05+00'
    )
  ),
  'revoked and missing acting sessions must leave target status and sessions unchanged'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_access = 'member'
      AND functional_grants = ARRAY[]::text[]
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003004',
      'synthetic-administrator-two@auth.invalid',
      'Synthetic Administrator Two',
      '2030-01-01 00:12:06+00',
      'role-followup-create-delegated'
    )
  )
  AND (
    SELECT functional_grants @> ARRAY['platform_administrator']
    FROM kovcheg.admin_grant_functional_grant(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003004',
      'platform_administrator',
      'owner-delegated',
      2,
      '2030-01-01 00:12:07+00',
      'role-followup-grant-platform-administrator'
    )
  ),
  'only the established owner may explicitly delegate platform administration'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-administrator-two@auth.invalid',
      '00000000-0000-4000-8000-000000003124',
      repeat('s', 43),
      '2030-01-01 00:13:00+00',
      '2030-01-01 00:23:00+00',
      5,
      interval '60 seconds',
      'auth-email-3124'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003124',
      repeat('s', 43),
      '2030-01-01 00:13:01+00',
      '00000000-0000-4000-8000-000000003224',
      repeat('s', 43),
      '2030-01-01 00:13:01+00',
      1020000,
      '2030-01-01 00:30:01+00'
    )
  ),
  'the second administrator must have one current acting session'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_status = 'deactivated'
    FROM kovcheg.admin_set_auth_account_status(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003004',
      'deactivated',
      '2030-01-01 00:13:02+00',
      'auth-admin-status-deactivate-actor'
    )
  ),
  'an active administrator must be able to deactivate another administrator'
);

DO $$
BEGIN
  BEGIN
    PERFORM kovcheg.admin_revoke_auth_session(
      repeat('s', 43),
      '00000000-0000-4000-8000-000000003003',
      '00000000-0000-4000-8000-000000003220',
      '2030-01-01 00:13:03+00',
      'auth-admin-failed-deactivated'
    );
    RAISE EXCEPTION 'a deactivated administrator session revoked a target session';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM *
    FROM kovcheg.admin_update_auth_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003099',
      'synthetic-missing@auth.invalid',
      'Missing Target',
      '2030-01-01 00:13:04+00',
      'auth-admin-failed-missing-target'
    );
    RAISE EXCEPTION 'a missing target was not distinguished from authorization failure';
  EXCEPTION WHEN no_data_found THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT session_id = '00000000-0000-4000-8000-000000003220'
    FROM kovcheg.authenticate_auth_session(
      repeat('n', 43),
      '2030-01-01 00:13:05+00'
    )
  ),
  'a deactivated acting administrator must fail without revoking the target session'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000003005'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003005',
      'synthetic-revoke-all@auth.invalid',
      'Synthetic Revoke All',
      '2030-01-01 00:14:00+00',
      'auth-admin-create-race-target'
    )
  ),
  'the concurrent revoke-all fixture account must be created atomically'
);

DO $$
DECLARE
  fixture_number integer;
  fixture_challenge_id uuid;
  fixture_session_id uuid;
  fixture_issued_at timestamptz;
  fixture_outcome varchar;
BEGIN
  FOR fixture_number IN 1..12 LOOP
    fixture_challenge_id := (
      '00000000-0000-4000-8002-' || pg_catalog.lpad(fixture_number::text, 12, '0')
    )::uuid;
    fixture_session_id := (
      '00000000-0000-4000-8003-' || pg_catalog.lpad(fixture_number::text, 12, '0')
    )::uuid;
    fixture_issued_at :=
      '2030-01-01 00:14:00+00'::timestamptz + fixture_number * interval '61 seconds';

    SELECT outcome INTO fixture_outcome
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-revoke-all@auth.invalid',
      fixture_challenge_id,
      pg_catalog.lpad(fixture_number::text, 43, 'c'),
      fixture_issued_at,
      fixture_issued_at + interval '10 minutes',
      5,
      interval '60 seconds',
      'auth-email-revoke-all-' || fixture_number::text
    );
    IF fixture_outcome <> 'issued' THEN
      RAISE EXCEPTION 'concurrent revoke-all challenge fixture was not issued';
    END IF;

    SELECT outcome INTO fixture_outcome
    FROM kovcheg.consume_auth_challenge_and_create_session(
      fixture_challenge_id,
      pg_catalog.lpad(fixture_number::text, 43, 'c'),
      fixture_issued_at + interval '500 milliseconds',
      fixture_session_id,
      pg_catalog.lpad(fixture_number::text, 43, 'z'),
      fixture_issued_at + interval '500 milliseconds',
      3600000,
      fixture_issued_at + interval '2 hours'
    );
    IF fixture_outcome <> 'authenticated' THEN
      RAISE EXCEPTION 'concurrent revoke-all session fixture was not created';
    END IF;
  END LOOP;
END;
$$;

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
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-member@auth.invalid',
      '00000000-0000-4000-8000-000000003126',
      repeat('u', 43),
      '2030-01-01 00:16:00+00',
      '2030-01-01 00:26:00+00',
      5,
      interval '60 seconds',
      'auth-email-3126'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000003126',
      repeat('u', 43),
      '2030-01-01 00:16:01+00',
      '00000000-0000-4000-8000-000000003226',
      repeat('x', 43),
      '2030-01-01 00:16:01+00',
      60000,
      '2030-01-01 00:26:01+00'
    )
  ),
  'the non-touch session validation fixture must create one bounded session'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000003002'
      AND session_id = '00000000-0000-4000-8000-000000003226'
      AND cardinality(auth_roles) = 1
      AND auth_roles[1] <> 'administrator'
    FROM kovcheg.validate_auth_session(
      repeat('x', 43),
      '2030-01-01 00:16:59+00'
    )
  ),
  'non-touch validation must return the active session principal'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.validate_auth_session(
      repeat('x', 43),
      '2030-01-01 00:17:01+00'
    )
  ),
  'non-touch validation must not extend the original idle expiry'
);

SELECT pg_temp.assert_true(
  kovcheg.revoke_auth_session_by_verifier(
    repeat('x', 43),
    '2030-01-01 00:17:02+00'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.validate_auth_session(
      repeat('x', 43),
      '2030-01-01 00:17:03+00'
    )
  ),
  'non-touch validation must reject a revoked session'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-member@auth.invalid',
      '00000000-0000-4000-8000-000000003109',
      repeat('k', 43),
      '2030-01-01 00:20:00+00',
      '2030-01-01 00:30:00+00',
      5,
      interval '60 seconds',
      'auth-email-3109'
    )
  ),
  'the concurrent verification fixture must have one live challenge'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.admin_grant_system_persona_operator(
      repeat('o', 43),
      '00000000-0000-4000-8000-000000003002',
      '00000000-0000-4000-8000-000000001001',
      '2030-01-01 00:20:30+00',
      'persona-grant-failed-ordinary'
    );
    RAISE EXCEPTION 'an ordinary session granted system persona authority';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT operator_account_id = '00000000-0000-4000-8000-000000003002'
      AND persona_account_id = '00000000-0000-4000-8000-000000001001'
      AND grant_status = 'active'
      AND granted_at = '2030-01-01 00:21:00+00'
      AND revoked_at IS NULL
    FROM kovcheg.admin_grant_system_persona_operator(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003002',
      '00000000-0000-4000-8000-000000001001',
      '2030-01-01 00:21:00+00',
      'persona-grant-operator-one'
    )
  ),
  'an administrator must grant one active operator-persona pair'
);

SELECT pg_temp.assert_true(
  (
    SELECT operator_account_id = '00000000-0000-4000-8000-000000003003'
      AND persona_account_id = '00000000-0000-4000-8000-000000001001'
      AND grant_status = 'active'
      AND granted_at = '2030-01-01 00:21:01+00'
      AND revoked_at IS NULL
    FROM kovcheg.admin_grant_system_persona_operator(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003003',
      '00000000-0000-4000-8000-000000001001',
      '2030-01-01 00:21:01+00',
      'persona-grant-operator-two'
    )
  ),
  'operator grants must be issued independently per person account'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.admin_grant_system_persona_operator(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003002',
      '00000000-0000-4000-8000-000000001001',
      '2030-01-01 00:21:01+00',
      'persona-grant-failed-duplicate'
    );
    RAISE EXCEPTION 'an active operator grant was duplicated';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;

  BEGIN
    PERFORM kovcheg.admin_revoke_system_persona_operator(
      repeat('o', 43),
      '00000000-0000-4000-8000-000000003003',
      '00000000-0000-4000-8000-000000001001',
      '2030-01-01 00:21:02+00',
      'persona-revoke-failed-ordinary'
    );
    RAISE EXCEPTION 'an ordinary session revoked system persona authority';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  kovcheg.admin_revoke_system_persona_operator(
    repeat('m', 43),
    '00000000-0000-4000-8000-000000003002',
    '00000000-0000-4000-8000-000000001001',
    '2030-01-01 00:21:02+00',
    'persona-revoke-operator-one'
  ),
  'an administrator must revoke one active operator-persona pair'
);

SELECT pg_temp.assert_true(
  NOT kovcheg.admin_revoke_system_persona_operator(
    repeat('m', 43),
    '00000000-0000-4000-8000-000000003002',
    '00000000-0000-4000-8000-000000001001',
    '2030-01-01 00:21:03+00',
    'persona-revoke-missing-retry'
  ),
  'repeating a revoked operator pair must be an ineffective no-op'
);

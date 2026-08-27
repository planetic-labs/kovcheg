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
  has_function_privilege(
    current_user,
    'kovcheg.issue_auth_email_challenge(text,uuid,text,timestamp with time zone,timestamp with time zone,integer,interval,character varying)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    current_user,
    'kovcheg.issue_auth_challenge_for_active_account(text,uuid,text,timestamp with time zone,timestamp with time zone,integer,interval)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    current_user,
    'kovcheg.activate_auth_personal_gate(text,uuid,text,text,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    current_user,
    'kovcheg.validate_auth_personal_gate_session(text,timestamp with time zone)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    current_user,
    'kovcheg.issue_auth_challenge_for_personal_gate(text,text,uuid,text,timestamp with time zone,timestamp with time zone,integer,interval,character varying)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    current_user,
    'kovcheg.extend_auth_personal_gate_after_login(text,text,timestamp with time zone)',
    'EXECUTE'
  ),
  'auth runtime must expose only the direct Variant E email challenge entrypoint'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000006001'
      AND email = 'variant.user+tag@auth.invalid'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000006001',
      'Variant.User+Tag@Auth.Invalid',
      'Synthetic Variant Account',
      '2030-01-01 00:30:00+00',
      'variant-email-account-create'
    )
  ),
  'Variant E setup must keep full-address case-folding without dot or tag rewriting'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
      AND challenge_id = '00000000-0000-4000-8000-000000006101'
      AND recipient = 'variant.user+tag@auth.invalid'
    FROM kovcheg.issue_auth_email_challenge(
      '  VARIANT.USER+TAG@AUTH.INVALID  ',
      '00000000-0000-4000-8000-000000006101',
      repeat('V', 43),
      '2030-01-01 00:30:01+00',
      '2030-01-01 00:40:01+00',
      5,
      interval '60 seconds',
      'variant-email-normalized'
    )
  ),
  'outer trim and case-folding must resolve the exact pre-created active account'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.validate_auth_session(
      repeat('N', 43),
      '2030-01-01 00:30:02+00'
    )
  ),
  'challenge issuance alone must not create an application session'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'neutral'
      AND challenge_id IS NULL
      AND recipient IS NULL
    FROM kovcheg.issue_auth_email_challenge(
      'variantuser+tag@auth.invalid',
      '00000000-0000-4000-8000-000000006102',
      repeat('W', 43),
      '2030-01-01 00:30:02+00',
      '2030-01-01 00:40:02+00',
      5,
      interval '60 seconds',
      'variant-email-dot-preserved'
    )
  )
  AND (
    SELECT outcome = 'neutral'
      AND challenge_id IS NULL
      AND recipient IS NULL
    FROM kovcheg.issue_auth_email_challenge(
      'variant.user@auth.invalid',
      '00000000-0000-4000-8000-000000006103',
      repeat('X', 43),
      '2030-01-01 00:30:03+00',
      '2030-01-01 00:40:03+00',
      5,
      interval '60 seconds',
      'variant-email-tag-preserved'
    )
  ),
  'dot removal and plus-tag stripping must not match another identity'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'authenticated'
      AND account_id = '00000000-0000-4000-8000-000000006001'
      AND session_id = '00000000-0000-4000-8000-000000006201'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000006101',
      repeat('V', 43),
      '2030-01-01 00:30:04+00',
      '00000000-0000-4000-8000-000000006201',
      repeat('N', 43),
      '2030-01-01 00:30:04+00',
      604800000,
      '2030-01-31 00:30:04+00'
    )
  ),
  'successful one-time consume must atomically create one application session'
);

SELECT pg_temp.assert_true(
  (
    SELECT session_id = '00000000-0000-4000-8000-000000006201'
    FROM kovcheg.validate_auth_session(
      repeat('N', 43),
      '2030-01-01 00:30:05+00'
    )
  ),
  'the application session must validate only after successful consume'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'invalid'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000006101',
      repeat('V', 43),
      '2030-01-01 00:30:06+00',
      '00000000-0000-4000-8000-000000006202',
      repeat('O', 43),
      '2030-01-01 00:30:06+00',
      604800000,
      '2030-01-31 00:30:06+00'
    )
  ),
  'a consumed OTP challenge must reject replay without another session'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000006002'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000006002',
      'synthetic-variant-deactivated@auth.invalid',
      'Synthetic Deactivated Variant Account',
      '2030-01-01 00:31:00+00',
      'variant-email-deactivated-create'
    )
  )
  AND (
    SELECT account_status = 'deactivated'
    FROM kovcheg.admin_set_auth_account_status(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000006002',
      'deactivated',
      '2030-01-01 00:31:01+00',
      'variant-email-deactivated-status'
    )
  )
  AND (
    SELECT outcome = 'neutral'
      AND challenge_id IS NULL
      AND recipient IS NULL
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-variant-deactivated@auth.invalid',
      '00000000-0000-4000-8000-000000006104',
      repeat('Y', 43),
      '2030-01-01 00:31:02+00',
      '2030-01-01 00:41:02+00',
      5,
      interval '60 seconds',
      'variant-email-deactivated-neutral'
    )
  ),
  'deactivated accounts must disclose no recipient and create no challenge or session'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000006003'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000006003',
      'synthetic-variant-attempts@auth.invalid',
      'Synthetic Attempts Account',
      '2030-01-01 00:32:00+00',
      'variant-email-attempts-create'
    )
  )
  AND (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-variant-attempts@auth.invalid',
      '00000000-0000-4000-8000-000000006105',
      repeat('Z', 43),
      '2030-01-01 00:32:01+00',
      '2030-01-01 00:42:01+00',
      5,
      interval '60 seconds',
      'variant-email-attempts-issued'
    )
  ),
  'the attempts fixture must receive one direct challenge'
);

SELECT pg_temp.assert_true(
  (
    SELECT bool_and(outcome = 'invalid')
    FROM generate_series(1, 5) AS attempt(number)
    CROSS JOIN LATERAL kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000006105',
      repeat('Q', 43),
      '2030-01-01 00:32:01+00'::timestamptz
        + (attempt.number * interval '1 second'),
      ('00000000-0000-4000-8003-' || lpad(attempt.number::text, 12, '0'))::uuid,
      lpad(attempt.number::text, 43, 'R'),
      '2030-01-01 00:32:01+00'::timestamptz
        + (attempt.number * interval '1 second'),
      604800000,
      '2030-01-31 00:32:01+00'
    )
  )
  AND (
    SELECT outcome = 'invalid'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000006105',
      repeat('Z', 43),
      '2030-01-01 00:32:10+00',
      '00000000-0000-4000-8000-000000006205',
      repeat('S', 43),
      '2030-01-01 00:32:10+00',
      604800000,
      '2030-01-31 00:32:10+00'
    )
  ),
  'five mismatches must exhaust the OTP without creating a session'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000006004'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000006004',
      'synthetic-variant-race@auth.invalid',
      'Synthetic Variant Race Account',
      '2030-01-01 00:33:00+00',
      'variant-email-race-account-create'
    )
  ),
  'the concurrency fixture must be a pre-created active account'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.issue_auth_email_challenge(
      'synthetic-variant-race@auth.invalid',
      '00000000-0000-4000-8000-000000006199',
      repeat('T', 43),
      '2030-01-01 00:33:01+00',
      '2030-01-01 00:43:01+00',
      4,
      interval '60 seconds',
      'variant-email-invalid-policy'
    );
    RAISE EXCEPTION 'a weakened OTP policy was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END;
$$;

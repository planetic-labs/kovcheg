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
    'kovcheg.auth_personal_gate_families',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    current_user,
    'kovcheg.auth_personal_gate_sessions',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.activate_auth_personal_gate(text,uuid,text,text,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.issue_auth_challenge_for_personal_gate(text,text,uuid,text,timestamp with time zone,timestamp with time zone,integer,interval,character varying)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.extend_auth_personal_gate_after_login(text,text,timestamp with time zone)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    current_user,
    'kovcheg.auth_personal_gate_audit(character varying,uuid,character varying,character varying,uuid,jsonb)',
    'EXECUTE'
  ),
  'the auth login must receive only the narrow personal-gate function surface'
);

DO $$
BEGIN
  BEGIN
    PERFORM kovcheg.admin_issue_auth_personal_gate(
      repeat('n', 43),
      '00000000-0000-4000-8000-000000003002',
      '00000000-0000-4000-8000-000000004099',
      repeat('F', 43),
      '2030-01-01 00:22:00+00',
      'gate-unauthorized-issue'
    );
    RAISE EXCEPTION 'an ordinary application session issued a personal gate';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM kovcheg.admin_issue_auth_personal_gate(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000003002',
      '00000000-0000-4000-8000-000000004098',
      repeat('E', 43),
      '2030-01-01 00:22:00+00',
      'invalid correlation id'
    );
    RAISE EXCEPTION 'an invalid gate audit correlation was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000004001'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000004001',
      'synthetic.member+gate@auth.invalid',
      'Synthetic Personal Gate',
      '2030-01-01 00:22:01+00',
      'gate-account-create-001'
    )
  ),
  'a pre-created account must exist before a personal gate is issued'
);

SELECT pg_temp.assert_true(
  kovcheg.admin_issue_auth_personal_gate(
    repeat('m', 43),
    '00000000-0000-4000-8000-000000004001',
    '00000000-0000-4000-8000-000000004101',
    repeat('G', 43),
    '2030-01-01 00:22:02+00',
    'gate-issue-001'
  ) = '00000000-0000-4000-8000-000000004101',
  'an active administrator must issue one UUID-bound personal gate family'
);

DO $$
BEGIN
  BEGIN
    PERFORM kovcheg.admin_issue_auth_personal_gate(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000004001',
      '00000000-0000-4000-8000-000000004198',
      repeat('D', 43),
      '2030-01-01 00:22:03+00',
      'gate-issue-duplicate'
    );
    RAISE EXCEPTION 'a second current gate family was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'invalid'
      AND account_id IS NULL
      AND family_id IS NULL
      AND gate_session_id IS NULL
    FROM kovcheg.activate_auth_personal_gate(
      repeat('Z', 43),
      '00000000-0000-4000-8000-000000004299',
      repeat('Z', 43),
      'synthetic-client-invalid-001',
      '2030-01-01 00:22:04+00',
      'gate-activate-invalid'
    )
  ),
  'an unknown verifier must fail with a neutral activation result'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'active'
      AND account_id = '00000000-0000-4000-8000-000000004001'
      AND family_id = '00000000-0000-4000-8000-000000004101'
      AND gate_session_id = '00000000-0000-4000-8000-000000004201'
      AND NOT reused
    FROM kovcheg.activate_auth_personal_gate(
      repeat('G', 43),
      '00000000-0000-4000-8000-000000004201',
      repeat('H', 43),
      'synthetic-client-gate-001',
      '2030-01-01 00:22:05+00',
      'gate-activate-001'
    )
  )
  AND (
    SELECT outcome = 'active'
      AND reused
      AND gate_session_id = '00000000-0000-4000-8000-000000004201'
    FROM kovcheg.activate_auth_personal_gate(
      repeat('G', 43),
      '00000000-0000-4000-8000-000000004201',
      repeat('H', 43),
      'synthetic-client-gate-001',
      '2030-01-01 00:22:06+00',
      'gate-activate-001-retry'
    )
  ),
  'same-client activation retries must be idempotent without replacing the cookie record'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000004001'
      AND family_id = '00000000-0000-4000-8000-000000004101'
      AND gate_session_id = '00000000-0000-4000-8000-000000004201'
      AND email_submission_allowed
      AND expires_at = '2030-01-08 00:22:05+00'::timestamptz
    FROM kovcheg.validate_auth_personal_gate_session(
      repeat('H', 43),
      '2030-01-01 00:22:07+00'
    )
  ),
  'gate validation must return only the bound technical identity and seven-day expiry'
);

DO $$
DECLARE
  attempt_number integer;
  attempt_outcome varchar;
BEGIN
  FOR attempt_number IN 1..5 LOOP
    SELECT outcome INTO attempt_outcome
    FROM kovcheg.issue_auth_challenge_for_personal_gate(
      repeat('H', 43),
      'synthetic.member@auth.invalid',
      '00000000-0000-4000-8000-000000004390',
      repeat('I', 43),
      '2030-01-01 00:23:00+00'::timestamptz
        + (attempt_number - 1) * interval '1 second',
      '2030-01-01 00:33:00+00'::timestamptz
        + (attempt_number - 1) * interval '1 second',
      5,
      interval '60 seconds',
      'gate-mismatch-pause-1'
    );

    IF (attempt_number < 5 AND attempt_outcome <> 'mismatch')
      OR (attempt_number = 5 AND attempt_outcome <> 'paused')
    THEN
      RAISE EXCEPTION 'unexpected first mismatch-window outcome: %', attempt_outcome;
    END IF;
  END LOOP;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'paused'
      AND recipient IS NULL
    FROM kovcheg.issue_auth_challenge_for_personal_gate(
      repeat('H', 43),
      '  SYNTHETIC.MEMBER+GATE@AUTH.INVALID  ',
      '00000000-0000-4000-8000-000000004391',
      repeat('I', 43),
      '2030-01-01 00:23:05+00',
      '2030-01-01 00:33:05+00',
      5,
      interval '60 seconds',
      'gate-paused-no-compare'
    )
  ),
  'a durable pause must prevent even an exact email comparison'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'issued'
      AND account_id = '00000000-0000-4000-8000-000000004001'
      AND challenge_id = '00000000-0000-4000-8000-000000004301'
      AND recipient = 'synthetic.member+gate@auth.invalid'
    FROM kovcheg.issue_auth_challenge_for_personal_gate(
      repeat('H', 43),
      '  SYNTHETIC.MEMBER+GATE@AUTH.INVALID  ',
      '00000000-0000-4000-8000-000000004301',
      repeat('I', 43),
      '2030-01-01 00:38:04+00',
      '2030-01-01 00:48:04+00',
      5,
      interval '60 seconds',
      'gate-challenge-001'
    )
  ),
  'outer trim and case folding must preserve dots and plus tags for UUID-bound matching'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'authenticated'
      AND account_id = '00000000-0000-4000-8000-000000004001'
      AND session_id = '00000000-0000-4000-8000-000000004401'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000004301',
      repeat('I', 43),
      '2030-01-01 00:38:05+00',
      '00000000-0000-4000-8000-000000004401',
      repeat('J', 43),
      '2030-01-01 00:38:05+00',
      3600000,
      '2030-01-02 00:38:05+00'
    )
  )
  AND kovcheg.extend_auth_personal_gate_after_login(
    repeat('H', 43),
    repeat('J', 43),
    '2030-01-01 00:38:06+00'
  ) = '2030-01-08 00:38:06+00'::timestamptz,
  'only a completed email challenge application-session may extend its gate session'
);

SELECT pg_temp.assert_true(
  kovcheg.extend_auth_personal_gate_after_login(
    repeat('H', 43),
    repeat('m', 43),
    '2030-01-01 00:38:07+00'
  ) IS NULL,
  'an unrelated application session must not extend a gate session'
);

DO $$
DECLARE
  pause_number integer;
  attempt_number integer;
  attempt_outcome varchar;
  window_start timestamptz;
BEGIN
  FOR pause_number IN 2..3 LOOP
    window_start := CASE pause_number
      WHEN 2 THEN '2030-01-01 00:39:00+00'::timestamptz
      ELSE '2030-01-01 00:54:04+00'::timestamptz
    END;

    FOR attempt_number IN 1..5 LOOP
      SELECT outcome INTO attempt_outcome
      FROM kovcheg.issue_auth_challenge_for_personal_gate(
        repeat('H', 43),
        'synthetic.member@auth.invalid',
        '00000000-0000-4000-8000-000000004392',
        repeat('I', 43),
        window_start + (attempt_number - 1) * interval '1 second',
        window_start + interval '10 minutes'
          + (attempt_number - 1) * interval '1 second',
        5,
        interval '60 seconds',
        'gate-mismatch-pause-' || pause_number
      );

      IF attempt_number < 5 AND attempt_outcome <> 'mismatch' THEN
        RAISE EXCEPTION 'unexpected mismatch outcome before threshold: %', attempt_outcome;
      END IF;
    END LOOP;

    IF pause_number = 2 AND attempt_outcome <> 'paused' THEN
      RAISE EXCEPTION 'the second threshold did not pause the family';
    ELSIF pause_number = 3 AND attempt_outcome <> 'suspended' THEN
      RAISE EXCEPTION 'the third threshold did not suspend the family';
    END IF;
  END LOOP;
END;
$$;

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM kovcheg.validate_auth_personal_gate_session(
      repeat('H', 43),
      '2030-01-01 00:54:09+00'
    )
  )
  AND (
    SELECT session_id = '00000000-0000-4000-8000-000000004401'
    FROM kovcheg.validate_auth_session(
      repeat('J', 43),
      '2030-01-01 00:54:09+00'
    )
  ),
  'family suspension must revoke gate sessions without revoking application sessions'
);

SELECT pg_temp.assert_true(
  kovcheg.admin_resume_auth_personal_gate(
    repeat('m', 43),
    '00000000-0000-4000-8000-000000004001',
    '00000000-0000-4000-8000-000000004101',
    '2030-01-01 00:55:00+00',
    'gate-resume-001'
  ),
  'an administrator decision must resume a suspended family without restoring sessions'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'active' AND NOT reused
    FROM kovcheg.activate_auth_personal_gate(
      repeat('G', 43),
      '00000000-0000-4000-8000-000000004202',
      repeat('K', 43),
      'synthetic-client-gate-002',
      '2030-01-01 00:55:01+00',
      'gate-activate-002'
    )
  ),
  'a resumed family must require a new independent gate session'
);

SELECT pg_temp.assert_true(
  (
    SELECT family_id = '00000000-0000-4000-8000-000000004102'
      AND revoked_gate_session_count = 1
    FROM kovcheg.admin_reissue_auth_personal_gate(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000004001',
      '00000000-0000-4000-8000-000000004102',
      repeat('L', 43),
      '2030-01-01 00:55:02+00',
      'gate-reissue-001'
    )
  )
  AND (
    SELECT outcome = 'invalid'
    FROM kovcheg.activate_auth_personal_gate(
      repeat('G', 43),
      '00000000-0000-4000-8000-000000004299',
      repeat('M', 43),
      'synthetic-client-old-code',
      '2030-01-01 00:55:03+00',
      'gate-old-code-invalid'
    )
  )
  AND (
    SELECT session_id = '00000000-0000-4000-8000-000000004401'
    FROM kovcheg.validate_auth_session(
      repeat('J', 43),
      '2030-01-01 00:55:03+00'
    )
  ),
  'reissue must revoke the old family and gate sessions but preserve application sessions'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'active'
    FROM kovcheg.activate_auth_personal_gate(
      repeat('L', 43),
      '00000000-0000-4000-8000-000000004203',
      repeat('N', 43),
      'synthetic-client-gate-003',
      '2030-01-01 00:55:04+00',
      'gate-activate-003'
    )
  )
  AND kovcheg.admin_revoke_auth_personal_gate(
    repeat('m', 43),
    '00000000-0000-4000-8000-000000004001',
    '00000000-0000-4000-8000-000000004102',
    '2030-01-01 00:55:05+00',
    'gate-revoke-001'
  ) = 1
  AND (
    SELECT session_id = '00000000-0000-4000-8000-000000004401'
    FROM kovcheg.validate_auth_session(
      repeat('J', 43),
      '2030-01-01 00:55:06+00'
    )
  ),
  'gate revocation must remain separate from application-session revocation'
);

SELECT pg_temp.assert_true(
  (
    kovcheg.admin_security_reset_auth_access(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000004001',
      '2030-01-01 00:55:07+00',
      'gate-security-reset-001'
    ) ->> 'revokedApplicationSessionCount'
  ) = '1',
  'the stronger security reset must report the revoked application session'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM kovcheg.validate_auth_session(
      repeat('J', 43),
      '2030-01-01 00:55:08+00'
    )
  ),
  'the separate stronger security reset must make application sessions invalid'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000004002'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000004002',
      'synthetic-race-gate@auth.invalid',
      'Synthetic Gate Race',
      '2030-01-01 00:56:00+00',
      'gate-race-account-create'
    )
  )
  AND kovcheg.admin_issue_auth_personal_gate(
    repeat('m', 43),
    '00000000-0000-4000-8000-000000004002',
    '00000000-0000-4000-8000-000000004110',
    repeat('R', 43),
    '2030-01-01 00:56:01+00',
    'gate-race-issue'
  ) = '00000000-0000-4000-8000-000000004110',
  'the concurrent activation fixture must have one current family'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000004003'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000004003',
      'synthetic-deactivation-gate@auth.invalid',
      'Synthetic Gate Deactivation',
      '2030-01-01 00:57:00+00',
      'gate-deactivation-account-create'
    )
  )
  AND kovcheg.admin_issue_auth_personal_gate(
    repeat('m', 43),
    '00000000-0000-4000-8000-000000004003',
    '00000000-0000-4000-8000-000000004120',
    repeat('T', 43),
    '2030-01-01 00:57:01+00',
    'gate-deactivation-issue'
  ) = '00000000-0000-4000-8000-000000004120'
  AND (
    SELECT outcome = 'active'
    FROM kovcheg.activate_auth_personal_gate(
      repeat('T', 43),
      '00000000-0000-4000-8000-000000004220',
      repeat('U', 43),
      'synthetic-client-deactivate',
      '2030-01-01 00:57:02+00',
      'gate-deactivation-activate'
    )
  )
  AND (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_challenge_for_personal_gate(
      repeat('U', 43),
      'synthetic-deactivation-gate@auth.invalid',
      '00000000-0000-4000-8000-000000004320',
      repeat('V', 43),
      '2030-01-01 00:57:03+00',
      '2030-01-01 01:07:03+00',
      5,
      interval '0 seconds',
      'gate-deactivation-challenge'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000004320',
      repeat('V', 43),
      '2030-01-01 00:57:04+00',
      '00000000-0000-4000-8000-000000004420',
      repeat('_', 43),
      '2030-01-01 00:57:04+00',
      3600000,
      '2030-01-02 00:57:04+00'
    )
  ),
  'the deactivation fixture must have both gate and application sessions'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_status = 'deactivated'
    FROM kovcheg.admin_set_auth_account_status(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000004003',
      'deactivated',
      '2030-01-01 00:57:05+00',
      'gate-deactivation-status'
    )
  ),
  'an administrator must commit the deactivation transition'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM kovcheg.validate_auth_personal_gate_session(
      repeat('U', 43),
      '2030-01-01 00:57:06+00'
    )
  )
  AND NOT EXISTS (
    SELECT 1 FROM kovcheg.validate_auth_session(
      repeat('_', 43),
      '2030-01-01 00:57:06+00'
    )
  ),
  'account deactivation must atomically revoke gate and application sessions'
);

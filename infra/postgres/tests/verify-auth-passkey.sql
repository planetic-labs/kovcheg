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
    'kovcheg.auth_passkey_credentials',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    current_user,
    'kovcheg.auth_passkey_assertion_evidence',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.register_auth_passkey(text,uuid,bytea,bytea,bigint,kovcheg.auth_passkey_transport[],uuid,text,boolean,boolean,boolean,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.read_auth_passkey_by_credential_id(bytea,timestamp with time zone)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.complete_auth_passkey_login(bytea,bigint,bigint,boolean,boolean,boolean,uuid,uuid,text,bigint,timestamp with time zone,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND NOT has_function_privilege(
    current_user,
    'kovcheg.auth_passkey_audit(character varying,uuid,character varying,uuid,jsonb)',
    'EXECUTE'
  ),
  'auth runtime must receive only the narrow passkey function surface'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000005001'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000005001',
      'synthetic-passkey-reset@auth.invalid',
      'Synthetic Passkey Reset',
      '2030-01-01 01:00:00+00',
      'passkey-reset-account-create'
    )
  )
  AND (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-passkey-reset@auth.invalid',
      '00000000-0000-4000-8000-000000005101',
      repeat('A', 43),
      '2030-01-01 01:00:01+00',
      '2030-01-01 01:10:01+00',
      5,
      interval '0 seconds'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000005101',
      repeat('A', 43),
      '2030-01-01 01:00:02+00',
      '00000000-0000-4000-8000-000000005201',
      repeat('B', 43),
      '2030-01-01 01:00:02+00',
      3600000,
      '2030-01-02 01:00:02+00'
    )
  ),
  'passkey registration fixture must start from a successful application login'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.register_auth_passkey(
      repeat('Z', 43),
      '00000000-0000-4000-8000-000000005398',
      decode(repeat('98', 32), 'hex'),
      decode(repeat('a8', 64), 'hex'),
      1,
      ARRAY['internal']::kovcheg.auth_passkey_transport[],
      '00000000-0000-4000-8000-000000005498',
      'packed',
      false,
      false,
      true,
      '2030-01-01 01:00:03+00',
      'passkey-register-unauthorized'
    );
    RAISE EXCEPTION 'an unknown application session registered a passkey';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM *
    FROM kovcheg.register_auth_passkey(
      repeat('B', 43),
      '00000000-0000-4000-8000-000000005399',
      decode(repeat('99', 32), 'hex'),
      decode(repeat('a9', 64), 'hex'),
      1,
      ARRAY['internal']::kovcheg.auth_passkey_transport[],
      '00000000-0000-4000-8000-000000005499',
      'packed',
      false,
      false,
      false,
      '2030-01-01 01:00:03+00',
      'passkey-register-uv-denied'
    );
    RAISE EXCEPTION 'registration without user verification was accepted';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT passkey_id = '00000000-0000-4000-8000-000000005301'
      AND account_id = '00000000-0000-4000-8000-000000005001'
    FROM kovcheg.register_auth_passkey(
      repeat('B', 43),
      '00000000-0000-4000-8000-000000005301',
      decode(repeat('a1', 32), 'hex'),
      decode(repeat('b1', 64), 'hex'),
      5,
      ARRAY['internal', 'hybrid', 'internal']::kovcheg.auth_passkey_transport[],
      '00000000-0000-4000-8000-000000005401',
      'packed',
      true,
      true,
      true,
      '2030-01-01 01:00:04+00',
      'passkey-register-primary'
    )
  )
  AND (
    SELECT passkey_id = '00000000-0000-4000-8000-000000005302'
    FROM kovcheg.register_auth_passkey(
      repeat('B', 43),
      '00000000-0000-4000-8000-000000005302',
      decode(repeat('a2', 32), 'hex'),
      decode(repeat('b2', 64), 'hex'),
      0,
      ARRAY['internal']::kovcheg.auth_passkey_transport[],
      '00000000-0000-4000-8000-000000005402',
      'none',
      false,
      false,
      true,
      '2030-01-01 01:00:05+00',
      'passkey-register-secondary'
    )
  ),
  'one pre-created UUID account must support several passkeys'
);

SELECT pg_temp.assert_true(
  (
    SELECT passkey_id = '00000000-0000-4000-8000-000000005301'
      AND account_id = '00000000-0000-4000-8000-000000005001'
      AND sign_count = 5
      AND transports = ARRAY['hybrid', 'internal']::kovcheg.auth_passkey_transport[]
      AND registered_backup_eligible
      AND registered_backup_state
    FROM kovcheg.read_auth_passkey_by_credential_id(
      decode(repeat('a1', 32), 'hex'),
      '2030-01-01 01:00:06+00'
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.read_auth_passkey_by_credential_id(
      decode(repeat('ff', 32), 'hex'),
      '2030-01-01 01:00:06+00'
    )
  ),
  'credential lookup must return only an active exact technical binding'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'authenticated'
      AND account_id = '00000000-0000-4000-8000-000000005001'
      AND session_id = '00000000-0000-4000-8000-000000005501'
      AND sign_count_status = 'not_advanced'
      AND resulting_sign_count = 5
      AND NOT reused
    FROM kovcheg.complete_auth_passkey_login(
      decode(repeat('a1', 32), 'hex'),
      5,
      5,
      true,
      true,
      true,
      '00000000-0000-4000-8000-000000005601',
      '00000000-0000-4000-8000-000000005501',
      repeat('C', 43),
      3600000,
      '2030-01-02 01:01:00+00',
      '2030-01-01 01:01:00+00',
      'passkey-login-not-advanced'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
      AND reused
      AND session_id = '00000000-0000-4000-8000-000000005501'
    FROM kovcheg.complete_auth_passkey_login(
      decode(repeat('a1', 32), 'hex'),
      5,
      5,
      true,
      true,
      true,
      '00000000-0000-4000-8000-000000005601',
      '00000000-0000-4000-8000-000000005501',
      repeat('C', 43),
      3600000,
      '2030-01-02 01:01:00+00',
      '2030-01-01 01:01:01+00',
      'passkey-login-not-advanced'
    )
  ),
  'a non-incremented counter must be recorded as risk evidence without sole denial'
);

SELECT pg_temp.assert_true(
  (
    SELECT outcome = 'authenticated'
      AND sign_count_status = 'regressed'
      AND resulting_sign_count = 5
    FROM kovcheg.complete_auth_passkey_login(
      decode(repeat('a1', 32), 'hex'),
      5,
      4,
      true,
      false,
      true,
      '00000000-0000-4000-8000-000000005602',
      '00000000-0000-4000-8000-000000005502',
      repeat('D', 43),
      3600000,
      '2030-01-02 01:02:00+00',
      '2030-01-01 01:02:00+00',
      'passkey-login-regressed'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
      AND sign_count_status = 'advanced'
      AND resulting_sign_count = 6
    FROM kovcheg.complete_auth_passkey_login(
      decode(repeat('a1', 32), 'hex'),
      5,
      6,
      true,
      false,
      true,
      '00000000-0000-4000-8000-000000005603',
      '00000000-0000-4000-8000-000000005503',
      repeat('E', 43),
      3600000,
      '2030-01-02 01:03:00+00',
      '2030-01-01 01:03:00+00',
      'passkey-login-advanced'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
      AND sign_count_status = 'not_supported'
      AND resulting_sign_count = 0
    FROM kovcheg.complete_auth_passkey_login(
      decode(repeat('a2', 32), 'hex'),
      0,
      0,
      false,
      false,
      true,
      '00000000-0000-4000-8000-000000005604',
      '00000000-0000-4000-8000-000000005504',
      repeat('F', 43),
      3600000,
      '2030-01-02 01:04:00+00',
      '2030-01-01 01:04:00+00',
      'passkey-login-not-supported'
    )
  ),
  'counter and synced-passkey signals must remain durable risk evidence'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.complete_auth_passkey_login(
      decode(repeat('ff', 32), 'hex'),
      0,
      0,
      false,
      false,
      true,
      '00000000-0000-4000-8000-000000005698',
      '00000000-0000-4000-8000-000000005598',
      repeat('Y', 43),
      3600000,
      '2030-01-02 01:04:00+00',
      '2030-01-01 01:04:00+00',
      'passkey-login-unknown'
    )
  ),
  'unknown credentials must fail closed without exposing an account'
);

DO $$
BEGIN
  BEGIN
    PERFORM *
    FROM kovcheg.complete_auth_passkey_login(
      decode(repeat('a2', 32), 'hex'),
      0,
      0,
      false,
      false,
      false,
      '00000000-0000-4000-8000-000000005699',
      '00000000-0000-4000-8000-000000005599',
      repeat('X', 43),
      3600000,
      '2030-01-02 01:04:00+00',
      '2030-01-01 01:04:00+00',
      'passkey-login-uv-denied'
    );
    RAISE EXCEPTION 'a login without user verification was accepted';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    kovcheg.admin_security_reset_auth_access(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000005001',
      '2030-01-01 01:05:00+00',
      'passkey-security-reset'
    ) ->> 'revokedPasskeyCount'
  ) = '2',
  'security reset must report every revoked passkey'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1
    FROM kovcheg.read_auth_passkey_by_credential_id(
      decode(repeat('a1', 32), 'hex'),
      '2030-01-01 01:05:01+00'
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.validate_auth_session(
      repeat('C', 43),
      '2030-01-01 01:05:01+00'
    )
  ),
  'security reset must atomically revoke passkeys and application sessions'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000005002'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000005002',
      'synthetic-passkey-deactivate@auth.invalid',
      'Synthetic Passkey Deactivation',
      '2030-01-01 01:06:00+00',
      'passkey-deactivation-account-create'
    )
  )
  AND (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-passkey-deactivate@auth.invalid',
      '00000000-0000-4000-8000-000000005102',
      repeat('G', 43),
      '2030-01-01 01:06:01+00',
      '2030-01-01 01:16:01+00',
      5,
      interval '0 seconds'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000005102',
      repeat('G', 43),
      '2030-01-01 01:06:02+00',
      '00000000-0000-4000-8000-000000005202',
      repeat('H', 43),
      '2030-01-01 01:06:02+00',
      3600000,
      '2030-01-02 01:06:02+00'
    )
  )
  AND (
    SELECT passkey_id = '00000000-0000-4000-8000-000000005303'
    FROM kovcheg.register_auth_passkey(
      repeat('H', 43),
      '00000000-0000-4000-8000-000000005303',
      decode(repeat('a3', 32), 'hex'),
      decode(repeat('b3', 64), 'hex'),
      2,
      ARRAY['usb']::kovcheg.auth_passkey_transport[],
      '00000000-0000-4000-8000-000000005403',
      'packed',
      false,
      false,
      true,
      '2030-01-01 01:06:03+00',
      'passkey-deactivation-register'
    )
  )
  AND (
    SELECT account_status = 'deactivated'
    FROM kovcheg.admin_set_auth_account_status(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000005002',
      'deactivated',
      '2030-01-01 01:06:04+00',
      'passkey-deactivation-status'
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.read_auth_passkey_by_credential_id(
      decode(repeat('a3', 32), 'hex'),
      '2030-01-01 01:06:05+00'
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM kovcheg.validate_auth_session(
      repeat('H', 43),
      '2030-01-01 01:06:05+00'
    )
  ),
  'account deactivation must fail closed for passkey and application sessions'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000005003'
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000005003',
      'synthetic-passkey-race@auth.invalid',
      'Synthetic Passkey Race',
      '2030-01-01 01:07:00+00',
      'passkey-race-account-create'
    )
  )
  AND (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_challenge_for_active_account(
      'synthetic-passkey-race@auth.invalid',
      '00000000-0000-4000-8000-000000005103',
      repeat('I', 43),
      '2030-01-01 01:07:01+00',
      '2030-01-01 01:17:01+00',
      5,
      interval '0 seconds'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000005103',
      repeat('I', 43),
      '2030-01-01 01:07:02+00',
      '00000000-0000-4000-8000-000000005203',
      repeat('J', 42) || '5',
      '2030-01-01 01:07:02+00',
      3600000,
      '2030-01-02 01:07:02+00'
    )
  )
  AND (
    SELECT passkey_id = '00000000-0000-4000-8000-000000005304'
    FROM kovcheg.register_auth_passkey(
      repeat('J', 42) || '5',
      '00000000-0000-4000-8000-000000005304',
      decode(repeat('a4', 32), 'hex'),
      decode(repeat('b4', 64), 'hex'),
      10,
      ARRAY['hybrid']::kovcheg.auth_passkey_transport[],
      '00000000-0000-4000-8000-000000005404',
      'packed',
      true,
      true,
      true,
      '2030-01-01 01:07:03+00',
      'passkey-race-register'
    )
  ),
  'the concurrent assertion fixture must hold one active passkey'
);

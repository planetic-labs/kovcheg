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
    'kovcheg.admin_list_role_capable_accounts(text,uuid,integer,timestamp with time zone)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.admin_read_role_capable_account(text,uuid,timestamp with time zone)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.read_own_auth_passkey_settings(text,timestamp with time zone)',
    'EXECUTE'
  )
  AND has_function_privilege(
    current_user,
    'kovcheg.revoke_own_auth_passkey(text,uuid,timestamp with time zone,character varying)',
    'EXECUTE'
  )
  AND NOT has_table_privilege(
    current_user,
    'kovcheg.account_auth_profiles',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    current_user,
    'kovcheg.account_domain_statuses',
    'SELECT,INSERT,UPDATE,DELETE'
  )
  AND NOT has_table_privilege(
    current_user,
    'kovcheg.auth_passkey_credentials',
    'SELECT,INSERT,UPDATE,DELETE'
  ),
  'auth runtime must receive only the narrow account and own-passkey surface'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000018001'
      AND account_status = 'active'
      AND functional_grants = ARRAY[]::text[]
    FROM kovcheg.admin_create_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000018001',
      'settings-member@auth.invalid',
      'Settings Member',
      '2030-01-01 00:30:00+00',
      'account-management-create-member'
    )
  )
  AND (
    SELECT outcome = 'issued'
    FROM kovcheg.issue_auth_email_challenge(
      'settings-member@auth.invalid',
      '00000000-0000-4000-8000-000000018101',
      repeat('L', 43),
      '2030-01-01 00:30:01+00',
      '2030-01-01 00:40:01+00',
      5,
      interval '60 seconds',
      'account-management-member-challenge'
    )
  )
  AND (
    SELECT outcome = 'authenticated'
    FROM kovcheg.consume_auth_challenge_and_create_session(
      '00000000-0000-4000-8000-000000018101',
      repeat('L', 43),
      '2030-01-01 00:30:02+00',
      '00000000-0000-4000-8000-000000018102',
      repeat('P', 42) || '8',
      '2030-01-01 00:30:02+00',
      3600000,
      '2030-01-02 00:30:02+00'
    )
  ),
  'the account-management fixture must use an ordinary application session'
);

CREATE TEMP TABLE account_page_one AS
SELECT *
FROM kovcheg.admin_list_role_capable_accounts(
  repeat('m', 43),
  NULL,
  2,
  '2030-01-01 00:30:03+00'
);

CREATE TEMP TABLE account_page_two AS
SELECT *
FROM kovcheg.admin_list_role_capable_accounts(
  repeat('m', 43),
  (SELECT account_id FROM account_page_one ORDER BY account_id DESC LIMIT 1),
  2,
  '2030-01-01 00:30:03+00'
);

SELECT pg_temp.assert_true(
  (SELECT count(*) = 2 AND bool_and(has_more) FROM account_page_one)
  AND (
    SELECT array_agg(account_id ORDER BY account_id) = array_agg(account_id)
    FROM account_page_one
  )
  AND NOT EXISTS (
    SELECT 1
    FROM account_page_one AS first_page
    JOIN account_page_two AS second_page USING (account_id)
  )
  AND (
    SELECT bool_and(
      account_id > (
        SELECT account_id FROM account_page_one ORDER BY account_id DESC LIMIT 1
      )
    )
    FROM account_page_two
  ),
  'administrator account listing must be bounded and use stable exclusive UUID pagination'
);

SELECT pg_temp.assert_true(
  (
    SELECT account_id = '00000000-0000-4000-8000-000000018001'
      AND email = 'settings-member@auth.invalid'
      AND display_name = 'Settings Member'
      AND account_access = 'member'
      AND account_status = 'active'
      AND domain_status = 'incubator_participant'
      AND functional_grants = ARRAY[]::text[]
      AND authorization_version = 1
      AND NOT is_server_owner
    FROM kovcheg.admin_read_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000018001',
      '2030-01-01 00:30:04+00'
    )
  ),
  'administrator detail must return current persisted account and authorization version'
);

DO $$
BEGIN
  BEGIN
    PERFORM * FROM kovcheg.admin_list_role_capable_accounts(
      repeat('P', 42) || '8', NULL, 20, '2030-01-01 00:30:05+00'
    );
    RAISE EXCEPTION 'an ordinary application session listed accounts';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM * FROM kovcheg.admin_read_role_capable_account(
      repeat('P', 42) || '8',
      '00000000-0000-4000-8000-000000018001',
      '2030-01-01 00:30:05+00'
    );
    RAISE EXCEPTION 'an ordinary application session read account detail';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;

  BEGIN
    PERFORM * FROM kovcheg.admin_read_role_capable_account(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000018099',
      '2030-01-01 00:30:05+00'
    );
    RAISE EXCEPTION 'a missing account returned an administrative detail';
  EXCEPTION WHEN no_data_found THEN
    NULL;
  END;

  BEGIN
    PERFORM * FROM kovcheg.admin_list_role_capable_accounts(
      repeat('m', 43), NULL, 0, '2030-01-01 00:30:05+00'
    );
    RAISE EXCEPTION 'an unbounded account page size was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  BEGIN
    PERFORM * FROM kovcheg.admin_list_role_capable_accounts(
      repeat('m', 43), NULL, 20, '2030-01-03 00:30:05+00'
    );
    RAISE EXCEPTION 'an expired administrator session listed accounts';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT NOT ever_added
      AND active_passkey_count = 0
      AND active_passkeys = '[]'::jsonb
    FROM kovcheg.read_own_auth_passkey_settings(
      repeat('P', 42) || '8',
      '2030-01-01 00:30:06+00'
    )
  ),
  'a current account without passkeys must receive one empty settings state'
);

SELECT * FROM kovcheg.register_auth_passkey(
  repeat('P', 42) || '8',
  '00000000-0000-4000-8000-000000018201',
  decode(repeat('d1', 32), 'hex'),
  decode(repeat('e1', 64), 'hex'),
  0,
  ARRAY['internal']::kovcheg.auth_passkey_transport[],
  '00000000-0000-4000-8000-000000018301',
  'none',
  true,
  false,
  true,
  '2030-01-01 00:30:07+00',
  'own-passkey-register-one'
);
SELECT * FROM kovcheg.register_auth_passkey(
  repeat('P', 42) || '8',
  '00000000-0000-4000-8000-000000018202',
  decode(repeat('d2', 32), 'hex'),
  decode(repeat('e2', 64), 'hex'),
  1,
  ARRAY['hybrid', 'internal']::kovcheg.auth_passkey_transport[],
  '00000000-0000-4000-8000-000000018302',
  'packed',
  true,
  true,
  true,
  '2030-01-01 00:30:08+00',
  'own-passkey-register-two'
);
SELECT * FROM kovcheg.register_auth_passkey(
  repeat('P', 42) || '8',
  '00000000-0000-4000-8000-000000018203',
  decode(repeat('d3', 32), 'hex'),
  decode(repeat('e3', 64), 'hex'),
  2,
  ARRAY['internal']::kovcheg.auth_passkey_transport[],
  '00000000-0000-4000-8000-000000018303',
  'packed',
  false,
  false,
  true,
  '2030-01-01 00:30:09+00',
  'own-passkey-register-race'
);

SELECT pg_temp.assert_true(
  (
    SELECT ever_added
      AND active_passkey_count = 3
      AND pg_catalog.jsonb_array_length(active_passkeys) = 3
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(active_passkeys) AS item(value)
        CROSS JOIN LATERAL pg_catalog.jsonb_object_keys(item.value) AS property(key)
        WHERE property.key NOT IN ('id', 'createdAt', 'lastUsedAt', 'status')
      )
      AND NOT active_passkeys::text ~* '(credential|public.?key|verifier|transport|aaguid|correlation)'
    FROM kovcheg.read_own_auth_passkey_settings(
      repeat('P', 42) || '8',
      '2030-01-01 00:30:10+00'
    )
  ),
  'own passkey settings must expose only safe stable metadata for active keys'
);

DO $$
BEGIN
  BEGIN
    PERFORM kovcheg.revoke_own_auth_passkey(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000018201',
      '2030-01-01 00:30:11+00',
      'own-passkey-foreign-revoke'
    );
    RAISE EXCEPTION 'an administrator revoked another account passkey through the own surface';
  EXCEPTION WHEN no_data_found THEN
    NULL;
  END;

  BEGIN
    PERFORM * FROM kovcheg.read_own_auth_passkey_settings(
      repeat('Z', 43),
      '2030-01-01 00:30:11+00'
    );
    RAISE EXCEPTION 'an unknown application session read passkey settings';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  kovcheg.revoke_own_auth_passkey(
    repeat('P', 42) || '8',
    '00000000-0000-4000-8000-000000018201',
    '2030-01-01 00:30:12+00',
    'own-passkey-revoke-one'
  )
  AND NOT kovcheg.revoke_own_auth_passkey(
    repeat('P', 42) || '8',
    '00000000-0000-4000-8000-000000018201',
    '2030-01-01 00:30:13+00',
    'own-passkey-revoke-one-retry'
  )
  AND kovcheg.revoke_own_auth_passkey(
    repeat('P', 42) || '8',
    '00000000-0000-4000-8000-000000018202',
    '2030-01-01 00:30:14+00',
    'own-passkey-revoke-two'
  )
  AND (
    SELECT ever_added
      AND active_passkey_count = 1
      AND pg_catalog.jsonb_array_length(active_passkeys) = 1
      AND active_passkeys -> 0 ->> 'id' = '00000000-0000-4000-8000-000000018203'
    FROM kovcheg.read_own_auth_passkey_settings(
      repeat('P', 42) || '8',
      '2030-01-01 00:30:15+00'
    )
  ),
  'own passkey revocation must be idempotent and preserve current server readback'
);

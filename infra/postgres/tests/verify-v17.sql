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
  kovcheg.current_migration_version() = '0017'
  AND (SELECT count(*) = 17 FROM kovcheg_meta.schema_migrations)
  AND to_regprocedure(
    'kovcheg.admin_list_role_capable_accounts(text,uuid,integer,timestamp with time zone)'
  ) IS NULL
  AND to_regprocedure(
    'kovcheg.read_own_auth_passkey_settings(text,timestamp with time zone)'
  ) IS NULL,
  'the v17 boundary must remain independently upgradeable before account settings reads'
);

INSERT INTO kovcheg.accounts (
  id, kind, status, created_at, activated_at
) VALUES (
  '00000000-0000-4000-8000-000000018917',
  'person',
  'active',
  '2030-01-01 00:17:00+00',
  '2030-01-01 00:17:00+00'
);
INSERT INTO kovcheg.account_auth_profiles (
  account_id, email, display_name, auth_role, created_at, updated_at
) VALUES (
  '00000000-0000-4000-8000-000000018917',
  'upgrade-v17@auth.invalid',
  'Upgrade V17',
  'student',
  '2030-01-01 00:17:00+00',
  '2030-01-01 00:17:00+00'
);
INSERT INTO kovcheg.account_domain_statuses (
  account_id, domain_status, authorization_version, changed_at
) VALUES (
  '00000000-0000-4000-8000-000000018917',
  'incubator_participant',
  4,
  '2030-01-01 00:17:00+00'
);
INSERT INTO kovcheg.auth_sessions (
  id, account_id, token_verifier, issued_at, last_seen_at,
  idle_lifetime_ms, idle_expires_at, absolute_expires_at
) VALUES (
  '00000000-0000-4000-8000-000000018918',
  '00000000-0000-4000-8000-000000018917',
  repeat('P', 42) || '7',
  '2030-01-01 00:17:00+00',
  '2030-01-01 00:17:00+00',
  3600000,
  '2030-01-01 01:17:00+00',
  '2030-01-02 00:17:00+00'
);
INSERT INTO kovcheg.auth_passkey_credentials (
  id, account_id, credential_id, public_key, sign_count, transports,
  aaguid, attestation_format, registered_backup_eligible,
  registered_backup_state, last_backup_eligible, last_backup_state,
  created_by_session_id, registration_correlation_id, created_at
) VALUES (
  '00000000-0000-4000-8000-000000018919',
  '00000000-0000-4000-8000-000000018917',
  decode(repeat('c1', 32), 'hex'),
  decode(repeat('c2', 64), 'hex'),
  7,
  ARRAY['hybrid', 'internal']::kovcheg.auth_passkey_transport[],
  '00000000-0000-4000-8000-000000018920',
  'packed',
  true,
  true,
  true,
  true,
  '00000000-0000-4000-8000-000000018918',
  'upgrade-v17-passkey',
  '2030-01-01 00:17:00+00'
);

SELECT pg_temp.assert_true(
  (
    SELECT profile.email = 'upgrade-v17@auth.invalid'
      AND domain.authorization_version = 4
      AND session.revoked_at IS NULL
      AND passkey.sign_count = 7
      AND passkey.revoked_at IS NULL
    FROM kovcheg.account_auth_profiles AS profile
    JOIN kovcheg.account_domain_statuses AS domain
      ON domain.account_id = profile.account_id
    JOIN kovcheg.auth_sessions AS session
      ON session.account_id = profile.account_id
    JOIN kovcheg.auth_passkey_credentials AS passkey
      ON passkey.account_id = profile.account_id
    WHERE profile.account_id = '00000000-0000-4000-8000-000000018917'
  ),
  'the v17 upgrade fixture must bind one active account, session, and passkey'
);

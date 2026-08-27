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
  kovcheg.current_migration_version() = '0015'
  AND (SELECT count(*) = 15 FROM kovcheg_meta.schema_migrations),
  'the fifteen-migration passkey boundary must remain complete'
);

SELECT pg_temp.assert_true(
  to_regprocedure(
    'kovcheg.complete_auth_passkey_login(bytea,bigint,bigint,boolean,boolean,boolean,uuid,uuid,text,bigint,timestamp with time zone,timestamp with time zone,character varying)'
  ) IS NOT NULL
  AND to_regprocedure(
    'kovcheg.issue_auth_challenge_for_personal_gate(text,text,uuid,text,timestamp with time zone,timestamp with time zone,integer,interval,character varying)'
  ) IS NOT NULL,
  'the v15 passkey and historical personal-gate boundaries must remain upgradeable'
);

INSERT INTO kovcheg.accounts (
  id,
  kind,
  status,
  activated_at
) VALUES (
  '00000000-0000-4000-8000-000000006900',
  'person',
  'active',
  '2030-01-01 00:00:00+00'
);

INSERT INTO kovcheg.account_auth_profiles (
  account_id,
  email,
  display_name,
  auth_role
) VALUES (
  '00000000-0000-4000-8000-000000006900',
  'synthetic-upgrade@auth.invalid',
  'Synthetic Upgrade Account',
  'student'
);

INSERT INTO kovcheg.auth_personal_gate_families (
  id,
  account_id,
  code_verifier,
  status,
  issued_at
) VALUES (
  '00000000-0000-4000-8000-000000006901',
  '00000000-0000-4000-8000-000000006900',
  repeat('F', 43),
  'active',
  '2030-01-01 00:01:00+00'
);

INSERT INTO kovcheg.auth_personal_gate_sessions (
  id,
  family_id,
  account_id,
  token_verifier,
  client_idempotency_key,
  issued_at,
  last_login_at,
  expires_at
) VALUES (
  '00000000-0000-4000-8000-000000006902',
  '00000000-0000-4000-8000-000000006901',
  '00000000-0000-4000-8000-000000006900',
  repeat('G', 43),
  'synthetic-upgrade-client',
  '2030-01-01 00:02:00+00',
  '2030-01-01 00:03:00+00',
  '2030-01-08 00:03:00+00'
);

INSERT INTO kovcheg.auth_email_challenges (
  id,
  account_id,
  code_verifier,
  issued_at,
  expires_at,
  used_at,
  max_attempts,
  gate_session_id
) VALUES (
  '00000000-0000-4000-8000-000000006903',
  '00000000-0000-4000-8000-000000006900',
  repeat('H', 43),
  '2030-01-01 00:04:00+00',
  '2030-01-01 00:14:00+00',
  '2030-01-01 00:05:00+00',
  5,
  '00000000-0000-4000-8000-000000006902'
), (
  '00000000-0000-4000-8000-000000006904',
  '00000000-0000-4000-8000-000000006900',
  repeat('I', 43),
  '2030-01-01 00:06:00+00',
  '2030-01-01 00:16:00+00',
  NULL,
  5,
  '00000000-0000-4000-8000-000000006902'
);

INSERT INTO kovcheg.auth_sessions (
  id,
  account_id,
  token_verifier,
  issued_at,
  last_seen_at,
  idle_lifetime_ms,
  idle_expires_at,
  absolute_expires_at,
  source_challenge_id
) VALUES (
  '00000000-0000-4000-8000-000000006905',
  '00000000-0000-4000-8000-000000006900',
  repeat('J', 43),
  '2030-01-01 00:05:00+00',
  '2030-01-01 00:05:00+00',
  3600000,
  '2030-01-01 01:05:00+00',
  '2030-01-01 02:05:00+00',
  '00000000-0000-4000-8000-000000006903'
);

INSERT INTO kovcheg.auth_passkey_credentials (
  id,
  account_id,
  credential_id,
  public_key,
  sign_count,
  transports,
  aaguid,
  attestation_format,
  registered_backup_eligible,
  registered_backup_state,
  last_backup_eligible,
  last_backup_state,
  created_by_session_id,
  registration_correlation_id,
  created_at
) VALUES (
  '00000000-0000-4000-8000-000000006906',
  '00000000-0000-4000-8000-000000006900',
  decode(repeat('c6', 32), 'hex'),
  decode(repeat('d6', 64), 'hex'),
  0,
  ARRAY['internal']::kovcheg.auth_passkey_transport[],
  '00000000-0000-4000-8000-000000006907',
  'none',
  true,
  true,
  true,
  true,
  '00000000-0000-4000-8000-000000006905',
  'synthetic-upgrade-passkey',
  '2030-01-01 00:05:30+00'
);

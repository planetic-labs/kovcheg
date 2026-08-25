CREATE FUNCTION pg_temp.ordinary_auth_role()
RETURNS kovcheg.auth_account_role
LANGUAGE sql
STABLE
AS $$
  SELECT role
  FROM pg_catalog.unnest(pg_catalog.enum_range(NULL::kovcheg.auth_account_role)) AS role
  WHERE role <> 'administrator'
  LIMIT 1;
$$;

DO $$
DECLARE
  account_id uuid;
BEGIN
  FOREACH account_id IN ARRAY ARRAY[
    '00000000-0000-4000-8000-000000002001'::uuid,
    '00000000-0000-4000-8000-000000002002'::uuid,
    '00000000-0000-4000-8000-000000002003'::uuid
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM kovcheg.accounts AS account WHERE account.id = account_id
    ) THEN
      PERFORM kovcheg.provision_account_with_starter_set(
        account_id,
        ('message-flow-session-fixture-' || account_id::text)::varchar
      );
    END IF;
  END LOOP;
END;
$$;

INSERT INTO kovcheg.account_auth_profiles (
  account_id,
  email,
  display_name,
  auth_role,
  created_at,
  updated_at
) VALUES
  (
    '00000000-0000-4000-8000-000000002001',
    'message-flow-operator-one@identity.invalid',
    'Message Flow Operator One',
    pg_temp.ordinary_auth_role(),
    '2030-01-01 00:00:00+00',
    '2030-01-01 00:00:00+00'
  ),
  (
    '00000000-0000-4000-8000-000000002002',
    'message-flow-operator-two@identity.invalid',
    'Message Flow Operator Two',
    pg_temp.ordinary_auth_role(),
    '2030-01-01 00:00:00+00',
    '2030-01-01 00:00:00+00'
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
  revoked_at
) VALUES
  (
    '00000000-0000-4000-8000-000000002201',
    '00000000-0000-4000-8000-000000002001',
    repeat('f', 43),
    '2030-01-01 00:00:00+00',
    '2030-01-01 00:00:00+00',
    7200000,
    '2030-01-01 02:00:00+00',
    '2030-01-01 03:00:00+00',
    NULL
  ),
  (
    '00000000-0000-4000-8000-000000002202',
    '00000000-0000-4000-8000-000000002002',
    repeat('g', 43),
    '2030-01-01 00:00:00+00',
    '2030-01-01 00:00:00+00',
    7200000,
    '2030-01-01 02:00:00+00',
    '2030-01-01 03:00:00+00',
    NULL
  );

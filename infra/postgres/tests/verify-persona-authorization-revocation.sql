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

DO $$
BEGIN
  PERFORM *
  FROM kovcheg.authorize_system_persona_action(
    '00000000-0000-4000-8000-000000009201',
    '00000000-0000-4000-8000-000000009001',
    '00000000-0000-4000-8000-000000009101',
    '2030-01-01 01:02:00+00'
  );
  RAISE EXCEPTION 'the next authorization ignored the revoked exact grant';
EXCEPTION WHEN insufficient_privilege THEN
  IF SQLERRM <> 'persona authorization failed' THEN
    RAISE EXCEPTION 'authorization failure was not neutral';
  END IF;
END;
$$;

SELECT pg_temp.assert_true(
  (
    SELECT operator_account_id = '00000000-0000-4000-8000-000000009002'
      AND persona_account_id = '00000000-0000-4000-8000-000000009101'
    FROM kovcheg.authorize_system_persona_action(
      '00000000-0000-4000-8000-000000009202',
      '00000000-0000-4000-8000-000000009002',
      '00000000-0000-4000-8000-000000009101',
      '2030-01-01 01:02:00+00'
    )
  ),
  'revoking one operator must not affect the other operator'
);

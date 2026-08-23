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
  kovcheg.current_migration_version() >= '0001',
  'the first migration must be recorded'
);
SELECT pg_temp.assert_true(
  (SELECT count(*) = 8 FROM pg_catalog.pg_inherits WHERE inhparent = 'kovcheg.messages'::regclass),
  'messages must have eight hash partitions'
);
SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 8
    FROM pg_catalog.pg_inherits
    WHERE inhparent = 'kovcheg.message_versions'::regclass
  ),
  'message versions must have eight hash partitions'
);
SELECT pg_temp.assert_true(
  pg_get_partkeydef('kovcheg.messages'::regclass) = 'HASH (chat_id)'
  AND pg_get_partkeydef('kovcheg.message_versions'::regclass) = 'HASH (chat_id)',
  'messages and versions must partition by chat_id'
);
SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid = 'kovcheg.messages'::regclass
      AND conname = 'messages_idempotency_unique'
      AND contype = 'u'
  ),
  'message idempotency must be enforced by a database unique constraint'
);
SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid = 'kovcheg.messages'::regclass
      AND conname = 'messages_chat_sequence_unique'
      AND contype = 'u'
  ),
  'chat sequence must be unique inside a chat'
);
SELECT pg_temp.assert_true(
  (
    SELECT data_type = 'uuid'
    FROM information_schema.columns
    WHERE table_schema = 'kovcheg'
      AND table_name = 'chat_memberships'
      AND column_name = 'id'
  ),
  'memberships must have UUID identifiers'
);
SELECT pg_temp.assert_true(
  (SELECT count(*) = 4 FROM kovcheg.starter_chat_blueprints WHERE is_required),
  'the required synthetic starter set must be non-empty and complete'
);
SELECT pg_temp.assert_true(
  (SELECT count(*) = 3 FROM kovcheg.accounts WHERE kind = 'synthetic_system'),
  'synthetic system fixtures must be present'
);
SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'kovcheg'
      AND table_name IN ('accounts', 'starter_chat_blueprints', 'chats', 'chat_memberships')
      AND column_name IN ('email', 'name', 'phone')
  ),
  'synthetic foundation fixtures must contain no identity or contact fields'
);

BEGIN;
UPDATE kovcheg.starter_chat_blueprints SET is_required = false;
DO $$
BEGIN
  BEGIN
    PERFORM kovcheg.provision_account_with_starter_set(
      '00000000-0000-4000-8000-000000002099',
      'database-zero-starter'
    );
    RAISE EXCEPTION 'zero starter set was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  IF EXISTS (
    SELECT 1 FROM kovcheg.accounts WHERE id = '00000000-0000-4000-8000-000000002099'
  ) THEN
    RAISE EXCEPTION 'failed provisioning was not atomic';
  END IF;
END;
$$;
ROLLBACK;

BEGIN;
CREATE FUNCTION pg_temp.reject_late_starter_chat()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.provisioned_for_account_id = '00000000-0000-4000-8000-000000002098'
    AND NEW.starter_blueprint_id = '00000000-0000-4000-8000-000000001103'
  THEN
    RAISE EXCEPTION 'synthetic late provisioning failure' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER verify_reject_late_starter_chat
BEFORE INSERT ON kovcheg.chats
FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_late_starter_chat();

DO $$
BEGIN
  BEGIN
    PERFORM kovcheg.provision_account_with_starter_set(
      '00000000-0000-4000-8000-000000002098',
      'database-partial-starter'
    );
    RAISE EXCEPTION 'partial starter failure was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;

  IF EXISTS (
    SELECT 1 FROM kovcheg.accounts
    WHERE id = '00000000-0000-4000-8000-000000002098'
  ) OR EXISTS (
    SELECT 1 FROM kovcheg.chats
    WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002098'
  ) OR EXISTS (
    SELECT 1 FROM kovcheg.chat_memberships
    WHERE account_id = '00000000-0000-4000-8000-000000002098'
  ) OR EXISTS (
    SELECT 1 FROM kovcheg.audit_events
    WHERE actor_account_id = '00000000-0000-4000-8000-000000002098'
  ) THEN
    RAISE EXCEPTION 'late provisioning failure left partial database state';
  END IF;
END;
$$;
ROLLBACK;

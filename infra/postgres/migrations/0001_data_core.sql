CREATE SCHEMA kovcheg AUTHORIZATION kovcheg_migration;
REVOKE ALL ON SCHEMA kovcheg FROM PUBLIC;

CREATE TYPE kovcheg.account_status AS ENUM ('active', 'deactivated');
CREATE TYPE kovcheg.account_kind AS ENUM ('person', 'synthetic_system');
CREATE TYPE kovcheg.chat_kind AS ENUM ('group', 'direct');
CREATE TYPE kovcheg.membership_role AS ENUM ('member', 'synthetic_system');
CREATE TYPE kovcheg.membership_status AS ENUM ('active', 'revoked');
CREATE TYPE kovcheg.event_outcome AS ENUM ('success', 'failure');

CREATE TABLE kovcheg.accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind kovcheg.account_kind NOT NULL DEFAULT 'person',
  status kovcheg.account_status NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  activated_at timestamptz,
  deactivated_at timestamptz,
  CONSTRAINT accounts_status_timestamps_check CHECK (
    (status = 'active' AND activated_at IS NOT NULL AND deactivated_at IS NULL)
    OR (status = 'deactivated' AND deactivated_at IS NOT NULL)
  )
);

CREATE TABLE kovcheg.starter_chat_blueprints (
  id uuid PRIMARY KEY,
  slug varchar(64) NOT NULL UNIQUE CHECK (slug ~ '^[a-z][a-z0-9-]{2,63}$'),
  chat_kind kovcheg.chat_kind NOT NULL,
  is_required boolean NOT NULL DEFAULT true,
  counterpart_account_id uuid REFERENCES kovcheg.accounts (id) ON DELETE RESTRICT,
  shared_chat_id uuid
);

CREATE TABLE kovcheg.chats (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind kovcheg.chat_kind NOT NULL,
  starter_blueprint_id uuid REFERENCES kovcheg.starter_chat_blueprints (id) ON DELETE RESTRICT,
  provisioned_for_account_id uuid REFERENCES kovcheg.accounts (id) ON DELETE RESTRICT,
  created_by_account_id uuid REFERENCES kovcheg.accounts (id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT chats_starter_unique UNIQUE NULLS NOT DISTINCT (
    provisioned_for_account_id,
    starter_blueprint_id
  ),
  CONSTRAINT chats_provisioning_shape_check CHECK (
    (provisioned_for_account_id IS NULL AND starter_blueprint_id IS NULL)
    OR starter_blueprint_id IS NOT NULL
  )
);

ALTER TABLE kovcheg.starter_chat_blueprints
  ADD CONSTRAINT starter_chat_blueprints_shared_chat_fk
  FOREIGN KEY (shared_chat_id) REFERENCES kovcheg.chats (id) ON DELETE RESTRICT;

CREATE TABLE kovcheg.chat_memberships (
  id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  chat_id uuid NOT NULL REFERENCES kovcheg.chats (id) ON DELETE CASCADE,
  account_id uuid NOT NULL REFERENCES kovcheg.accounts (id) ON DELETE RESTRICT,
  role kovcheg.membership_role NOT NULL DEFAULT 'member',
  status kovcheg.membership_status NOT NULL DEFAULT 'active',
  joined_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  PRIMARY KEY (chat_id, account_id),
  CONSTRAINT chat_memberships_status_timestamps_check CHECK (
    (status = 'active' AND revoked_at IS NULL)
    OR (status = 'revoked' AND revoked_at IS NOT NULL)
  )
);

CREATE INDEX chat_memberships_account_active_idx
  ON kovcheg.chat_memberships (account_id, chat_id)
  WHERE status = 'active';

CREATE TABLE kovcheg.chat_counters (
  chat_id uuid PRIMARY KEY REFERENCES kovcheg.chats (id) ON DELETE CASCADE,
  next_sequence bigint NOT NULL DEFAULT 1 CHECK (next_sequence > 0)
);

CREATE FUNCTION kovcheg.initialize_chat_counter()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  INSERT INTO kovcheg.chat_counters (chat_id) VALUES (NEW.id);
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.initialize_chat_counter() FROM PUBLIC;

CREATE TRIGGER chats_initialize_counter
AFTER INSERT ON kovcheg.chats
FOR EACH ROW EXECUTE FUNCTION kovcheg.initialize_chat_counter();

CREATE FUNCTION kovcheg.allocate_chat_sequence(p_chat_id uuid)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  allocated_sequence bigint;
BEGIN
  UPDATE kovcheg.chat_counters
  SET next_sequence = next_sequence + 1
  WHERE chat_id = p_chat_id
  RETURNING next_sequence - 1 INTO allocated_sequence;

  IF allocated_sequence IS NULL THEN
    RAISE EXCEPTION 'chat counter is unavailable' USING ERRCODE = '23503';
  END IF;

  RETURN allocated_sequence;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.allocate_chat_sequence(uuid) FROM PUBLIC;

CREATE TABLE kovcheg.messages (
  chat_id uuid NOT NULL REFERENCES kovcheg.chats (id) ON DELETE RESTRICT,
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  sender_account_id uuid NOT NULL,
  chat_sequence bigint NOT NULL,
  client_idempotency_key varchar(128) NOT NULL,
  content_fingerprint varchar(64) NOT NULL,
  body text NOT NULL,
  correlation_id varchar(128) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (chat_id, id),
  CONSTRAINT messages_sender_membership_fk
    FOREIGN KEY (chat_id, sender_account_id)
    REFERENCES kovcheg.chat_memberships (chat_id, account_id) ON DELETE RESTRICT,
  CONSTRAINT messages_chat_sequence_unique UNIQUE (chat_id, chat_sequence),
  CONSTRAINT messages_idempotency_unique UNIQUE (
    chat_id,
    sender_account_id,
    client_idempotency_key
  ),
  CONSTRAINT messages_chat_sequence_check CHECK (chat_sequence > 0),
  CONSTRAINT messages_idempotency_key_check CHECK (
    client_idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  ),
  CONSTRAINT messages_content_fingerprint_check CHECK (content_fingerprint ~ '^[0-9a-f]{64}$'),
  CONSTRAINT messages_body_check CHECK (char_length(body) BETWEEN 1 AND 20000),
  CONSTRAINT messages_correlation_id_check CHECK (
    correlation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  )
) PARTITION BY HASH (chat_id);

DO $$
BEGIN
  FOR partition_number IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE kovcheg.messages_p%s PARTITION OF kovcheg.messages FOR VALUES WITH (MODULUS 8, REMAINDER %s)',
      partition_number,
      partition_number
    );
  END LOOP;
END;
$$;

CREATE FUNCTION kovcheg.assign_chat_sequence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  NEW.chat_sequence := kovcheg.allocate_chat_sequence(NEW.chat_id);
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.assign_chat_sequence() FROM PUBLIC;

CREATE TRIGGER messages_assign_chat_sequence
BEFORE INSERT ON kovcheg.messages
FOR EACH ROW EXECUTE FUNCTION kovcheg.assign_chat_sequence();

CREATE TABLE kovcheg.message_versions (
  chat_id uuid NOT NULL,
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  message_id uuid NOT NULL,
  version_number integer NOT NULL,
  editor_account_id uuid NOT NULL,
  body text NOT NULL,
  content_fingerprint varchar(64) NOT NULL,
  correlation_id varchar(128) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (chat_id, id),
  CONSTRAINT message_versions_message_fk
    FOREIGN KEY (chat_id, message_id)
    REFERENCES kovcheg.messages (chat_id, id) ON DELETE RESTRICT,
  CONSTRAINT message_versions_editor_membership_fk
    FOREIGN KEY (chat_id, editor_account_id)
    REFERENCES kovcheg.chat_memberships (chat_id, account_id) ON DELETE RESTRICT,
  CONSTRAINT message_versions_number_unique UNIQUE (chat_id, message_id, version_number),
  CONSTRAINT message_versions_number_check CHECK (version_number > 0),
  CONSTRAINT message_versions_body_check CHECK (char_length(body) BETWEEN 1 AND 20000),
  CONSTRAINT message_versions_content_fingerprint_check CHECK (
    content_fingerprint ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT message_versions_correlation_id_check CHECK (
    correlation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  )
) PARTITION BY HASH (chat_id);

DO $$
BEGIN
  FOR partition_number IN 0..7 LOOP
    EXECUTE format(
      'CREATE TABLE kovcheg.message_versions_p%s PARTITION OF kovcheg.message_versions FOR VALUES WITH (MODULUS 8, REMAINDER %s)',
      partition_number,
      partition_number
    );
  END LOOP;
END;
$$;

CREATE FUNCTION kovcheg.create_initial_message_version()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  INSERT INTO kovcheg.message_versions (
    chat_id,
    message_id,
    version_number,
    editor_account_id,
    body,
    content_fingerprint,
    correlation_id,
    created_at
  ) VALUES (
    NEW.chat_id,
    NEW.id,
    1,
    NEW.sender_account_id,
    NEW.body,
    NEW.content_fingerprint,
    NEW.correlation_id,
    NEW.created_at
  );
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.create_initial_message_version() FROM PUBLIC;

CREATE TRIGGER messages_create_initial_version
AFTER INSERT ON kovcheg.messages
FOR EACH ROW EXECUTE FUNCTION kovcheg.create_initial_message_version();

CREATE TABLE kovcheg.chat_read_states (
  id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  chat_id uuid NOT NULL,
  account_id uuid NOT NULL,
  last_read_sequence bigint NOT NULL DEFAULT 0 CHECK (last_read_sequence >= 0),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (chat_id, account_id),
  CONSTRAINT chat_read_states_membership_fk
    FOREIGN KEY (chat_id, account_id)
    REFERENCES kovcheg.chat_memberships (chat_id, account_id) ON DELETE CASCADE
);

CREATE TABLE kovcheg.outbox_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  aggregate_type varchar(64) NOT NULL CHECK (aggregate_type ~ '^[a-z][a-z0-9._-]{1,63}$'),
  aggregate_id uuid NOT NULL,
  event_name varchar(96) NOT NULL CHECK (event_name ~ '^[a-z][a-z0-9._-]{1,95}$'),
  idempotency_key varchar(128) NOT NULL UNIQUE,
  correlation_id varchar(128) NOT NULL,
  migration_version varchar(32) NOT NULL,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  delivered_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  CONSTRAINT outbox_events_idempotency_key_check CHECK (
    idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  ),
  CONSTRAINT outbox_events_correlation_id_check CHECK (
    correlation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  ),
  CONSTRAINT outbox_events_migration_version_check CHECK (
    migration_version ~ '^[0-9]{4}$'
  )
);

CREATE INDEX outbox_events_pending_idx
  ON kovcheg.outbox_events (available_at, occurred_at, id)
  WHERE delivered_at IS NULL;

CREATE TABLE kovcheg.audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  correlation_id varchar(128) NOT NULL,
  migration_version varchar(32) NOT NULL,
  actor_account_id uuid REFERENCES kovcheg.accounts (id) ON DELETE RESTRICT,
  action varchar(96) NOT NULL CHECK (action ~ '^[a-z][a-z0-9._-]{1,95}$'),
  target_type varchar(64) NOT NULL CHECK (target_type ~ '^[a-z][a-z0-9._-]{1,63}$'),
  target_id uuid,
  outcome kovcheg.event_outcome NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT audit_events_correlation_id_check CHECK (
    correlation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  ),
  CONSTRAINT audit_events_migration_version_check CHECK (migration_version ~ '^[0-9]{4}$')
);

CREATE INDEX audit_events_correlation_idx ON kovcheg.audit_events (correlation_id, occurred_at);
CREATE INDEX audit_events_target_idx ON kovcheg.audit_events (target_type, target_id, occurred_at);

CREATE TABLE kovcheg.operation_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  correlation_id varchar(128) NOT NULL,
  migration_version varchar(32) NOT NULL,
  service varchar(32) NOT NULL CHECK (service ~ '^[a-z][a-z0-9-]{1,31}$'),
  event_name varchar(96) NOT NULL CHECK (event_name ~ '^[a-z][a-z0-9._-]{1,95}$'),
  outcome kovcheg.event_outcome NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT operation_events_correlation_id_check CHECK (
    correlation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  ),
  CONSTRAINT operation_events_migration_version_check CHECK (migration_version ~ '^[0-9]{4}$')
);

CREATE INDEX operation_events_correlation_idx
  ON kovcheg.operation_events (correlation_id, occurred_at);

CREATE FUNCTION kovcheg.reject_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.reject_append_only_mutation() FROM PUBLIC;

CREATE TRIGGER audit_events_reject_mutation
BEFORE UPDATE OR DELETE ON kovcheg.audit_events
FOR EACH ROW EXECUTE FUNCTION kovcheg.reject_append_only_mutation();
CREATE TRIGGER audit_events_reject_truncate
BEFORE TRUNCATE ON kovcheg.audit_events
FOR EACH STATEMENT EXECUTE FUNCTION kovcheg.reject_append_only_mutation();
CREATE TRIGGER operation_events_reject_mutation
BEFORE UPDATE OR DELETE ON kovcheg.operation_events
FOR EACH ROW EXECUTE FUNCTION kovcheg.reject_append_only_mutation();
CREATE TRIGGER operation_events_reject_truncate
BEFORE TRUNCATE ON kovcheg.operation_events
FOR EACH STATEMENT EXECUTE FUNCTION kovcheg.reject_append_only_mutation();

CREATE FUNCTION kovcheg.current_migration_version()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg_meta
AS $$
  SELECT max(version) FROM kovcheg_meta.schema_migrations;
$$;

REVOKE ALL ON FUNCTION kovcheg.current_migration_version() FROM PUBLIC;

CREATE FUNCTION kovcheg.append_audit_event(
  p_correlation_id varchar,
  p_migration_version varchar,
  p_actor_account_id uuid,
  p_action varchar,
  p_target_type varchar,
  p_target_id uuid,
  p_outcome kovcheg.event_outcome,
  p_details jsonb
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  event_id uuid;
BEGIN
  INSERT INTO kovcheg.audit_events (
    correlation_id,
    migration_version,
    actor_account_id,
    action,
    target_type,
    target_id,
    outcome,
    details
  ) VALUES (
    p_correlation_id,
    p_migration_version,
    p_actor_account_id,
    p_action,
    p_target_type,
    p_target_id,
    p_outcome,
    p_details
  ) RETURNING id INTO event_id;
  RETURN event_id;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.append_audit_event(
  varchar,
  varchar,
  uuid,
  varchar,
  varchar,
  uuid,
  kovcheg.event_outcome,
  jsonb
) FROM PUBLIC;

CREATE FUNCTION kovcheg.append_operation_event(
  p_correlation_id varchar,
  p_migration_version varchar,
  p_service varchar,
  p_event_name varchar,
  p_outcome kovcheg.event_outcome,
  p_metadata jsonb
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  event_id uuid;
BEGIN
  INSERT INTO kovcheg.operation_events (
    correlation_id,
    migration_version,
    service,
    event_name,
    outcome,
    metadata
  ) VALUES (
    p_correlation_id,
    p_migration_version,
    p_service,
    p_event_name,
    p_outcome,
    p_metadata
  ) RETURNING id INTO event_id;
  RETURN event_id;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.append_operation_event(
  varchar,
  varchar,
  varchar,
  varchar,
  kovcheg.event_outcome,
  jsonb
) FROM PUBLIC;

INSERT INTO kovcheg.accounts (id, kind, status, activated_at) VALUES
  ('00000000-0000-4000-8000-000000001001', 'synthetic_system', 'active', clock_timestamp()),
  ('00000000-0000-4000-8000-000000001002', 'synthetic_system', 'active', clock_timestamp()),
  ('00000000-0000-4000-8000-000000001003', 'synthetic_system', 'active', clock_timestamp());

INSERT INTO kovcheg.starter_chat_blueprints (
  id,
  slug,
  chat_kind,
  counterpart_account_id
) VALUES
  ('00000000-0000-4000-8000-000000001101', 'starter-community', 'group', NULL),
  (
    '00000000-0000-4000-8000-000000001102',
    'starter-guide',
    'direct',
    '00000000-0000-4000-8000-000000001001'
  ),
  (
    '00000000-0000-4000-8000-000000001103',
    'starter-support',
    'direct',
    '00000000-0000-4000-8000-000000001002'
  ),
  (
    '00000000-0000-4000-8000-000000001104',
    'starter-coordinator',
    'direct',
    '00000000-0000-4000-8000-000000001003'
  );

INSERT INTO kovcheg.chats (
  id,
  kind,
  starter_blueprint_id,
  created_by_account_id
) VALUES (
  '00000000-0000-4000-8000-000000001201',
  'group',
  '00000000-0000-4000-8000-000000001101',
  '00000000-0000-4000-8000-000000001001'
);

UPDATE kovcheg.starter_chat_blueprints
SET shared_chat_id = '00000000-0000-4000-8000-000000001201'
WHERE id = '00000000-0000-4000-8000-000000001101';

ALTER TABLE kovcheg.starter_chat_blueprints
  ADD CONSTRAINT starter_chat_blueprints_shape_check CHECK (
    (chat_kind = 'group' AND shared_chat_id IS NOT NULL AND counterpart_account_id IS NULL)
    OR (chat_kind = 'direct' AND shared_chat_id IS NULL AND counterpart_account_id IS NOT NULL)
  );

INSERT INTO kovcheg.chat_memberships (chat_id, account_id, role) VALUES
  (
    '00000000-0000-4000-8000-000000001201',
    '00000000-0000-4000-8000-000000001001',
    'synthetic_system'
  ),
  (
    '00000000-0000-4000-8000-000000001201',
    '00000000-0000-4000-8000-000000001002',
    'synthetic_system'
  ),
  (
    '00000000-0000-4000-8000-000000001201',
    '00000000-0000-4000-8000-000000001003',
    'synthetic_system'
  );

CREATE FUNCTION kovcheg.provision_account_with_starter_set(
  p_account_id uuid,
  p_correlation_id varchar
)
RETURNS TABLE (provisioned_account_id uuid, starter_chat_count integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  blueprint record;
  direct_chat_id uuid;
  required_count integer;
  migration_version text;
BEGIN
  SELECT count(*)::integer
  INTO required_count
  FROM kovcheg.starter_chat_blueprints
  WHERE is_required;

  IF required_count = 0 THEN
    RAISE EXCEPTION 'required starter chat set is empty' USING ERRCODE = '23514';
  END IF;

  INSERT INTO kovcheg.accounts (id, status, activated_at)
  VALUES (p_account_id, 'active', clock_timestamp());

  FOR blueprint IN
    SELECT *
    FROM kovcheg.starter_chat_blueprints
    WHERE is_required
    ORDER BY slug
  LOOP
    IF blueprint.shared_chat_id IS NOT NULL THEN
      INSERT INTO kovcheg.chat_memberships (chat_id, account_id)
      VALUES (blueprint.shared_chat_id, p_account_id);
    ELSE
      INSERT INTO kovcheg.chats (
        kind,
        starter_blueprint_id,
        provisioned_for_account_id,
        created_by_account_id
      ) VALUES (
        blueprint.chat_kind,
        blueprint.id,
        p_account_id,
        p_account_id
      ) RETURNING id INTO direct_chat_id;

      INSERT INTO kovcheg.chat_memberships (chat_id, account_id, role) VALUES
        (direct_chat_id, p_account_id, 'member'),
        (direct_chat_id, blueprint.counterpart_account_id, 'synthetic_system');
    END IF;
  END LOOP;

  SELECT count(*)::integer
  INTO starter_chat_count
  FROM kovcheg.chat_memberships
  WHERE account_id = p_account_id AND status = 'active';

  IF starter_chat_count = 0 THEN
    RAISE EXCEPTION 'account provisioning produced an empty starter set' USING ERRCODE = '23514';
  END IF;

  migration_version := kovcheg.current_migration_version();
  IF migration_version IS NULL THEN
    RAISE EXCEPTION 'migration metadata is unavailable' USING ERRCODE = '55000';
  END IF;

  INSERT INTO kovcheg.audit_events (
    correlation_id,
    migration_version,
    actor_account_id,
    action,
    target_type,
    target_id,
    outcome,
    details
  ) VALUES (
    p_correlation_id,
    migration_version,
    p_account_id,
    'account.provisioned',
    'account',
    p_account_id,
    'success',
    jsonb_build_object('starterChatCount', starter_chat_count)
  );

  provisioned_account_id := p_account_id;
  RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.provision_account_with_starter_set(uuid, varchar) FROM PUBLIC;

REVOKE ALL ON ALL TABLES IN SCHEMA kovcheg FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA kovcheg FROM PUBLIC;
GRANT USAGE ON SCHEMA kovcheg TO kovcheg_runtime, kovcheg_audit;
GRANT USAGE ON TYPE
  kovcheg.account_status,
  kovcheg.account_kind,
  kovcheg.chat_kind,
  kovcheg.membership_role,
  kovcheg.membership_status,
  kovcheg.event_outcome
TO kovcheg_runtime, kovcheg_audit;

GRANT SELECT ON
  kovcheg.accounts,
  kovcheg.chats,
  kovcheg.chat_memberships,
  kovcheg.chat_read_states,
  kovcheg.messages,
  kovcheg.message_versions,
  kovcheg.outbox_events
TO kovcheg_runtime;
GRANT INSERT ON kovcheg.messages, kovcheg.chat_read_states, kovcheg.outbox_events
TO kovcheg_runtime;
GRANT UPDATE (last_read_sequence, updated_at) ON kovcheg.chat_read_states
TO kovcheg_runtime;
GRANT EXECUTE ON FUNCTION kovcheg.provision_account_with_starter_set(uuid, varchar)
TO kovcheg_runtime;
GRANT EXECUTE ON FUNCTION kovcheg.current_migration_version()
TO kovcheg_runtime, kovcheg_audit;
GRANT EXECUTE ON FUNCTION kovcheg.append_audit_event(
  varchar,
  varchar,
  uuid,
  varchar,
  varchar,
  uuid,
  kovcheg.event_outcome,
  jsonb
) TO kovcheg_audit;
GRANT EXECUTE ON FUNCTION kovcheg.append_operation_event(
  varchar,
  varchar,
  varchar,
  varchar,
  kovcheg.event_outcome,
  jsonb
) TO kovcheg_audit;

ALTER DEFAULT PRIVILEGES FOR ROLE kovcheg_migration IN SCHEMA kovcheg
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE kovcheg_migration IN SCHEMA kovcheg
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

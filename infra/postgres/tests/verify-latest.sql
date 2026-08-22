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
  kovcheg.current_migration_version() = '0003',
  'the foundation review migration must be recorded'
);
SELECT pg_temp.assert_true(
  (SELECT count(*) = 3 FROM kovcheg_meta.schema_migrations),
  'exactly three checksummed migrations must be applied'
);
SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 2
    FROM information_schema.columns
    WHERE table_schema = 'kovcheg'
      AND table_name = 'outbox_events'
      AND column_name IN ('claim_token', 'claim_expires_at')
  ),
  'the v2 outbox claim metadata must remain available'
);
SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid = 'kovcheg.outbox_events'::regclass
      AND conname = 'outbox_events_claim_shape_check'
      AND convalidated
  ),
  'the additive outbox claim constraint must remain validated'
);
SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM pg_catalog.pg_indexes
    WHERE schemaname = 'kovcheg' AND indexname = 'outbox_events_expired_claim_idx'
  ),
  'the expired-claim index must remain available'
);

SELECT pg_temp.assert_true(
  NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid = 'kovcheg.chats'::regclass AND conname = 'chats_starter_unique'
  )
  AND EXISTS (
    SELECT 1 FROM pg_catalog.pg_indexes
    WHERE schemaname = 'kovcheg' AND indexname = 'chats_provisioned_starter_unique'
  )
  AND EXISTS (
    SELECT 1 FROM pg_catalog.pg_indexes
    WHERE schemaname = 'kovcheg' AND indexname = 'chats_shared_starter_unique'
  ),
  'starter uniqueness must not limit ordinary chats with two NULL values'
);

BEGIN;
INSERT INTO kovcheg.chats (id, kind, created_by_account_id) VALUES
  ('00000000-0000-4000-8000-000000001202', 'direct', '00000000-0000-4000-8000-000000001001'),
  ('00000000-0000-4000-8000-000000001203', 'group', '00000000-0000-4000-8000-000000001001');
SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 2
    FROM kovcheg.chats
    WHERE id IN (
      '00000000-0000-4000-8000-000000001202',
      '00000000-0000-4000-8000-000000001203'
    )
  ),
  'more than one ordinary chat must be insertable'
);
ROLLBACK;

SELECT pg_temp.assert_true(
  (SELECT count(*) = 3 FROM kovcheg.account_platform_roles),
  'the synthetic authorization fixtures must cover three distinct platform roles'
);
SELECT pg_temp.assert_true(
  (
    SELECT audience_kind = 'all_active_accounts'
      AND posting_policy = 'all_active_members'
    FROM kovcheg.chats
    WHERE id = '00000000-0000-4000-8000-000000001201'
  ),
  'the shared starter chat must expose explicit audience and posting policies'
);
SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1
    FROM kovcheg.chat_service_labels
    WHERE chat_id = '00000000-0000-4000-8000-000000001201' AND label = 'primary'
  ),
  'the shared starter chat must expose a separate service label'
);
SELECT pg_temp.assert_true(
  kovcheg.can_account_read_chat(
    '00000000-0000-4000-8000-000000002001',
    '00000000-0000-4000-8000-000000001201'
  )
  AND kovcheg.can_account_manage_chat_members(
    '00000000-0000-4000-8000-000000001001',
    '00000000-0000-4000-8000-000000001201'
  )
  AND kovcheg.can_account_manage_chat_members(
    '00000000-0000-4000-8000-000000001002',
    '00000000-0000-4000-8000-000000001201'
  )
  AND NOT kovcheg.can_account_manage_chat_members(
    '00000000-0000-4000-8000-000000002001',
    '00000000-0000-4000-8000-000000001201'
  )
  AND kovcheg.can_account_assign_chat_labels(
    '00000000-0000-4000-8000-000000001002',
    '00000000-0000-4000-8000-000000001201'
  ),
  'PostgreSQL authorization functions must enforce membership, chat administration, and platform roles'
);

BEGIN;
UPDATE kovcheg.chats
SET posting_policy = 'chat_administrators'
WHERE id = '00000000-0000-4000-8000-000000001201';
SELECT pg_temp.assert_true(
  kovcheg.can_account_post_to_chat(
    '00000000-0000-4000-8000-000000001001',
    '00000000-0000-4000-8000-000000001201'
  )
  AND NOT kovcheg.can_account_post_to_chat(
    '00000000-0000-4000-8000-000000002001',
    '00000000-0000-4000-8000-000000001201'
  ),
  'administrator-only posting policy must deny an ordinary active member'
);

UPDATE kovcheg.chats
SET posting_policy = 'platform_roles'
WHERE id = '00000000-0000-4000-8000-000000001201';
INSERT INTO kovcheg.chat_allowed_posting_roles (chat_id, role)
VALUES ('00000000-0000-4000-8000-000000001201', 'warrior');
SELECT pg_temp.assert_true(
  kovcheg.can_account_post_to_chat(
    '00000000-0000-4000-8000-000000001002',
    '00000000-0000-4000-8000-000000001201'
  )
  AND NOT kovcheg.can_account_post_to_chat(
    '00000000-0000-4000-8000-000000002001',
    '00000000-0000-4000-8000-000000001201'
  ),
  'role-based posting policy must use explicit PostgreSQL assignments'
);
ROLLBACK;

BEGIN;
DO $$
DECLARE
  membership_uuid uuid;
  absent_message_sequence bigint;
  closed_boundary bigint;
  reopened_boundary bigint;
BEGIN
  SELECT id INTO membership_uuid
  FROM kovcheg.chat_memberships
  WHERE chat_id = '00000000-0000-4000-8000-000000001201'
    AND account_id = '00000000-0000-4000-8000-000000002001';

  UPDATE kovcheg.chat_memberships
  SET status = 'revoked', revoked_at = clock_timestamp()
  WHERE id = membership_uuid;

  IF kovcheg.can_account_read_chat(
    '00000000-0000-4000-8000-000000002001',
    '00000000-0000-4000-8000-000000001201'
  ) THEN
    RAISE EXCEPTION 'revoked membership retained current read access';
  END IF;

  INSERT INTO kovcheg.messages (
    chat_id,
    sender_account_id,
    client_idempotency_key,
    content_fingerprint,
    body,
    correlation_id
  ) VALUES (
    '00000000-0000-4000-8000-000000001201',
    '00000000-0000-4000-8000-000000001001',
    'membership-gap-001',
    'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    'Synthetic membership gap message',
    'database-membership-gap-001'
  ) RETURNING chat_sequence INTO absent_message_sequence;

  UPDATE kovcheg.chat_memberships
  SET status = 'active',
      joined_at = revoked_at + interval '1 microsecond',
      revoked_at = NULL
  WHERE id = membership_uuid;

  SELECT max(revoked_after_sequence), max(joined_after_sequence)
    FILTER (WHERE revoked_at IS NULL)
  INTO closed_boundary, reopened_boundary
  FROM kovcheg.chat_membership_periods
  WHERE membership_id = membership_uuid;

  IF (
    SELECT count(*) <> 2 OR count(*) FILTER (WHERE revoked_at IS NULL) <> 1
    FROM kovcheg.chat_membership_periods
    WHERE membership_id = membership_uuid
  ) OR NOT (
    closed_boundary < absent_message_sequence
    AND reopened_boundary >= absent_message_sequence
  ) THEN
    RAISE EXCEPTION 'membership periods did not preserve the absent sequence interval';
  END IF;
END;
$$;
ROLLBACK;

DO $$
DECLARE
  target_chat_id uuid;
  counter_before bigint;
  counter_after bigint;
  message_count_before bigint;
  message_count_after bigint;
BEGIN
  SELECT id INTO target_chat_id
  FROM kovcheg.chats
  WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001'
  ORDER BY id
  LIMIT 1;

  SELECT next_sequence INTO counter_before
  FROM kovcheg.chat_counters WHERE chat_id = target_chat_id;
  SELECT count(*) INTO message_count_before
  FROM kovcheg.messages WHERE chat_id = target_chat_id;

  INSERT INTO kovcheg.messages (
    chat_id,
    sender_account_id,
    client_idempotency_key,
    content_fingerprint,
    body,
    correlation_id
  ) VALUES (
    target_chat_id,
    '00000000-0000-4000-8000-000000002001',
    'message-001',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'Synthetic first message',
    'database-message-idempotent-retry'
  ) ON CONFLICT ON CONSTRAINT messages_idempotency_unique DO NOTHING;

  SELECT next_sequence INTO counter_after
  FROM kovcheg.chat_counters WHERE chat_id = target_chat_id;
  SELECT count(*) INTO message_count_after
  FROM kovcheg.messages WHERE chat_id = target_chat_id;

  IF counter_after <> counter_before OR message_count_after <> message_count_before THEN
    RAISE EXCEPTION 'idempotent ON CONFLICT retry created a chat sequence gap';
  END IF;
END;
$$;

SELECT pg_temp.assert_true(
  kovcheg.event_metadata_is_sanitized('{"messageId":"00000000-0000-4000-8000-000000000001"}'::jsonb)
  AND NOT kovcheg.event_metadata_is_sanitized('{"nested":{"authToken":"technical-placeholder"}}'::jsonb),
  'event metadata sanitizer must allow technical identifiers and reject sensitive key shapes recursively'
);
SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 3
    FROM pg_catalog.pg_constraint
    WHERE conname IN (
      'outbox_events_sanitized_payload_check',
      'audit_events_sanitized_details_check',
      'operation_events_sanitized_metadata_check'
    )
      AND convalidated
  ),
  'outbox, audit, and operation event metadata constraints must be validated'
);
SELECT pg_temp.assert_true(
  (
    SELECT count(*) = 3
    FROM pg_catalog.pg_attribute AS attribute
    JOIN pg_catalog.pg_description AS description
      ON description.objoid = attribute.attrelid
      AND description.objsubid = attribute.attnum
    WHERE (attribute.attrelid, attribute.attname) IN (
      ('kovcheg.outbox_events'::regclass, 'payload'),
      ('kovcheg.audit_events'::regclass, 'details'),
      ('kovcheg.operation_events'::regclass, 'metadata')
    )
      AND description.description LIKE 'Sanitized technical identifiers%'
  ),
  'event JSON columns must publish the sanitization contract in the PostgreSQL catalog'
);

DO $$
BEGIN
  BEGIN
    INSERT INTO kovcheg.outbox_events (
      aggregate_type,
      aggregate_id,
      event_name,
      idempotency_key,
      correlation_id,
      migration_version,
      payload
    ) VALUES (
      'database',
      '00000000-0000-4000-8000-000000002001',
      'database.sanitizer-negative',
      'outbox-sanitizer-negative',
      'database-sanitizer-negative',
      '0003',
      '{"messageBody":"must-not-enter-events"}'::jsonb
    );
    RAISE EXCEPTION 'sensitive event metadata was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END;
$$;

SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM kovcheg.messages
    WHERE sender_account_id = '00000000-0000-4000-8000-000000002001'
  )
  AND EXISTS (
    SELECT 1 FROM kovcheg.outbox_events
    WHERE idempotency_key = 'outbox-message-001' AND claim_token IS NULL
  ),
  'pre-v3 message and outbox data must remain readable'
);

INSERT INTO kovcheg.outbox_events (
  aggregate_type,
  aggregate_id,
  event_name,
  idempotency_key,
  correlation_id,
  migration_version,
  payload
) VALUES (
  'database',
  '00000000-0000-4000-8000-000000002001',
  'database.compatibility-check',
  'outbox-compatible-v3-shape',
  'database-compatibility-v3',
  '0003',
  '{"fixture":"synthetic"}'::jsonb
);

SELECT pg_temp.assert_true(
  EXISTS (
    SELECT 1 FROM kovcheg.outbox_events
    WHERE idempotency_key = 'outbox-compatible-v3-shape'
      AND claim_token IS NULL
      AND claim_expires_at IS NULL
  ),
  'the pre-v2 insert shape must remain compatible after v3'
);

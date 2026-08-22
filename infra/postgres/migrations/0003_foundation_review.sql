ALTER TABLE kovcheg.chats
  DROP CONSTRAINT chats_starter_unique;

CREATE UNIQUE INDEX chats_provisioned_starter_unique
  ON kovcheg.chats (provisioned_for_account_id, starter_blueprint_id)
  WHERE provisioned_for_account_id IS NOT NULL AND starter_blueprint_id IS NOT NULL;

CREATE UNIQUE INDEX chats_shared_starter_unique
  ON kovcheg.chats (starter_blueprint_id)
  WHERE provisioned_for_account_id IS NULL AND starter_blueprint_id IS NOT NULL;

CREATE TYPE kovcheg.platform_role AS ENUM ('master', 'warrior', 'platform_administrator');
CREATE TYPE kovcheg.chat_audience_kind AS ENUM ('explicit_members', 'all_active_accounts');
CREATE TYPE kovcheg.chat_posting_policy AS ENUM (
  'all_active_members',
  'chat_administrators',
  'platform_roles'
);
CREATE TYPE kovcheg.chat_service_label AS ENUM ('primary', 'warrior', 'team', 'retreat');

CREATE TABLE kovcheg.account_platform_roles (
  account_id uuid NOT NULL REFERENCES kovcheg.accounts (id) ON DELETE CASCADE,
  role kovcheg.platform_role NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (account_id, role)
);

ALTER TABLE kovcheg.chats
  ADD COLUMN audience_kind kovcheg.chat_audience_kind NOT NULL DEFAULT 'explicit_members',
  ADD COLUMN posting_policy kovcheg.chat_posting_policy NOT NULL DEFAULT 'all_active_members',
  ADD CONSTRAINT chats_direct_audience_check CHECK (
    kind = 'group' OR audience_kind = 'explicit_members'
  );

ALTER TABLE kovcheg.chat_memberships
  ADD COLUMN is_administrator boolean NOT NULL DEFAULT false;

CREATE TABLE kovcheg.chat_allowed_posting_roles (
  chat_id uuid NOT NULL REFERENCES kovcheg.chats (id) ON DELETE CASCADE,
  role kovcheg.platform_role NOT NULL,
  PRIMARY KEY (chat_id, role)
);

CREATE TABLE kovcheg.chat_service_labels (
  chat_id uuid NOT NULL REFERENCES kovcheg.chats (id) ON DELETE CASCADE,
  label kovcheg.chat_service_label NOT NULL,
  assigned_by_account_id uuid NOT NULL REFERENCES kovcheg.accounts (id) ON DELETE RESTRICT,
  assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (chat_id, label)
);

CREATE FUNCTION kovcheg.enforce_group_chat_service_label()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM kovcheg.chats
    WHERE id = NEW.chat_id AND kind = 'group'
  ) THEN
    RAISE EXCEPTION 'service labels are available only for group chats'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.enforce_group_chat_service_label() FROM PUBLIC;

CREATE TRIGGER chat_service_labels_require_group
BEFORE INSERT OR UPDATE ON kovcheg.chat_service_labels
FOR EACH ROW EXECUTE FUNCTION kovcheg.enforce_group_chat_service_label();

CREATE TABLE kovcheg.chat_membership_periods (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  membership_id uuid NOT NULL REFERENCES kovcheg.chat_memberships (id) ON DELETE CASCADE,
  joined_at timestamptz NOT NULL,
  joined_after_sequence bigint NOT NULL CHECK (joined_after_sequence >= 0),
  revoked_at timestamptz,
  revoked_after_sequence bigint,
  CONSTRAINT chat_membership_periods_revocation_shape_check CHECK (
    (revoked_at IS NULL AND revoked_after_sequence IS NULL)
    OR (
      revoked_at IS NOT NULL
      AND revoked_after_sequence IS NOT NULL
      AND revoked_after_sequence >= joined_after_sequence
      AND revoked_at >= joined_at
    )
  )
);

CREATE UNIQUE INDEX chat_membership_periods_one_open_unique
  ON kovcheg.chat_membership_periods (membership_id)
  WHERE revoked_at IS NULL;

CREATE INDEX chat_membership_periods_membership_history_idx
  ON kovcheg.chat_membership_periods (membership_id, joined_at, revoked_at);

INSERT INTO kovcheg.chat_membership_periods (
  membership_id,
  joined_at,
  joined_after_sequence,
  revoked_at,
  revoked_after_sequence
)
SELECT
  membership.id,
  membership.joined_at,
  0,
  membership.revoked_at,
  CASE
    WHEN membership.revoked_at IS NULL THEN NULL
    ELSE GREATEST(counter.next_sequence - 1, 0)
  END
FROM kovcheg.chat_memberships AS membership
JOIN kovcheg.chat_counters AS counter ON counter.chat_id = membership.chat_id;

CREATE FUNCTION kovcheg.track_chat_membership_period()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  boundary_sequence bigint;
  affected_periods integer;
BEGIN
  SELECT next_sequence - 1
  INTO boundary_sequence
  FROM kovcheg.chat_counters
  WHERE chat_id = NEW.chat_id;

  IF boundary_sequence IS NULL THEN
    RAISE EXCEPTION 'chat counter is unavailable for membership boundary'
      USING ERRCODE = '23503';
  END IF;

  IF TG_OP = 'INSERT' THEN
    INSERT INTO kovcheg.chat_membership_periods (
      membership_id,
      joined_at,
      joined_after_sequence,
      revoked_at,
      revoked_after_sequence
    ) VALUES (
      NEW.id,
      NEW.joined_at,
      boundary_sequence,
      NEW.revoked_at,
      CASE WHEN NEW.status = 'revoked' THEN boundary_sequence ELSE NULL END
    );
    RETURN NEW;
  END IF;

  IF OLD.status = 'active' AND NEW.status = 'revoked' THEN
    UPDATE kovcheg.chat_membership_periods
    SET revoked_at = NEW.revoked_at,
        revoked_after_sequence = boundary_sequence
    WHERE membership_id = NEW.id AND revoked_at IS NULL;
    GET DIAGNOSTICS affected_periods = ROW_COUNT;
    IF affected_periods <> 1 THEN
      RAISE EXCEPTION 'active membership period is unavailable'
        USING ERRCODE = '55000';
    END IF;
  ELSIF OLD.status = 'revoked' AND NEW.status = 'active' THEN
    IF NEW.joined_at <= OLD.revoked_at THEN
      RAISE EXCEPTION 'rejoined membership must have a new joined_at boundary'
        USING ERRCODE = '23514';
    END IF;
    INSERT INTO kovcheg.chat_membership_periods (
      membership_id,
      joined_at,
      joined_after_sequence
    ) VALUES (
      NEW.id,
      NEW.joined_at,
      boundary_sequence
    );
  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.track_chat_membership_period() FROM PUBLIC;

CREATE TRIGGER chat_memberships_track_period
AFTER INSERT OR UPDATE OF status, joined_at, revoked_at ON kovcheg.chat_memberships
FOR EACH ROW EXECUTE FUNCTION kovcheg.track_chat_membership_period();

CREATE FUNCTION kovcheg.account_has_platform_role(
  p_account_id uuid,
  p_role kovcheg.platform_role
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM kovcheg.account_platform_roles
    WHERE account_id = p_account_id AND role = p_role
  );
$$;

REVOKE ALL ON FUNCTION kovcheg.account_has_platform_role(uuid, kovcheg.platform_role)
FROM PUBLIC;

CREATE FUNCTION kovcheg.can_account_read_chat(p_account_id uuid, p_chat_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM kovcheg.accounts AS account
    JOIN kovcheg.chat_memberships AS membership
      ON membership.account_id = account.id
    WHERE account.id = p_account_id
      AND account.status = 'active'
      AND membership.chat_id = p_chat_id
      AND membership.status = 'active'
  );
$$;

REVOKE ALL ON FUNCTION kovcheg.can_account_read_chat(uuid, uuid) FROM PUBLIC;

CREATE FUNCTION kovcheg.can_account_post_to_chat(p_account_id uuid, p_chat_id uuid)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  posting_policy kovcheg.chat_posting_policy;
  membership_is_administrator boolean;
BEGIN
  SELECT chat.posting_policy, membership.is_administrator
  INTO posting_policy, membership_is_administrator
  FROM kovcheg.accounts AS account
  JOIN kovcheg.chat_memberships AS membership
    ON membership.account_id = account.id
  JOIN kovcheg.chats AS chat ON chat.id = membership.chat_id
  WHERE account.id = p_account_id
    AND account.status = 'active'
    AND membership.chat_id = p_chat_id
    AND membership.status = 'active';

  IF NOT FOUND THEN
    RETURN false;
  END IF;
  IF posting_policy = 'all_active_members' OR membership_is_administrator THEN
    RETURN true;
  END IF;
  IF posting_policy = 'chat_administrators' THEN
    RETURN false;
  END IF;

  RETURN EXISTS (
    SELECT 1
    FROM kovcheg.account_platform_roles AS account_role
    JOIN kovcheg.chat_allowed_posting_roles AS allowed_role
      ON allowed_role.role = account_role.role
    WHERE account_role.account_id = p_account_id
      AND allowed_role.chat_id = p_chat_id
  );
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.can_account_post_to_chat(uuid, uuid) FROM PUBLIC;

CREATE FUNCTION kovcheg.can_account_manage_chat_members(p_account_id uuid, p_chat_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM kovcheg.accounts AS account
    JOIN kovcheg.chat_memberships AS membership
      ON membership.account_id = account.id
    WHERE account.id = p_account_id
      AND account.status = 'active'
      AND membership.chat_id = p_chat_id
      AND membership.status = 'active'
      AND (
        membership.is_administrator
        OR EXISTS (
          SELECT 1
          FROM kovcheg.account_platform_roles AS account_role
          WHERE account_role.account_id = p_account_id
            AND account_role.role IN ('master', 'warrior', 'platform_administrator')
        )
      )
  );
$$;

REVOKE ALL ON FUNCTION kovcheg.can_account_manage_chat_members(uuid, uuid) FROM PUBLIC;

CREATE FUNCTION kovcheg.can_account_assign_chat_labels(p_account_id uuid, p_chat_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM kovcheg.accounts AS account
    JOIN kovcheg.chat_memberships AS membership
      ON membership.account_id = account.id
    JOIN kovcheg.chats AS chat ON chat.id = membership.chat_id
    JOIN kovcheg.account_platform_roles AS account_role
      ON account_role.account_id = account.id
    WHERE account.id = p_account_id
      AND account.status = 'active'
      AND membership.chat_id = p_chat_id
      AND membership.status = 'active'
      AND chat.kind = 'group'
      AND account_role.role IN ('master', 'warrior', 'platform_administrator')
  );
$$;

REVOKE ALL ON FUNCTION kovcheg.can_account_assign_chat_labels(uuid, uuid) FROM PUBLIC;

CREATE FUNCTION kovcheg.event_metadata_is_sanitized(p_metadata jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  metadata_key text;
  metadata_value jsonb;
  normalized_key text;
BEGIN
  IF p_metadata IS NULL THEN
    RETURN false;
  END IF;

  IF jsonb_typeof(p_metadata) = 'object' THEN
    FOR metadata_key, metadata_value IN
      SELECT key, value FROM pg_catalog.jsonb_each(p_metadata)
    LOOP
      normalized_key := pg_catalog.lower(
        pg_catalog.regexp_replace(metadata_key, '([a-z0-9])([A-Z])', '\1_\2', 'g')
      );
      IF normalized_key IN ('message', 'content')
        OR normalized_key LIKE '%_message'
        OR normalized_key ~ '(^|_)(body|text|email|login_code|one_time_code|otp|token|cookie|secret|password|credential|phone|full_name|user_content|raw_content)(_|$)'
      THEN
        RETURN false;
      END IF;
      IF jsonb_typeof(metadata_value) IN ('object', 'array')
        AND NOT kovcheg.event_metadata_is_sanitized(metadata_value)
      THEN
        RETURN false;
      END IF;
    END LOOP;
  ELSIF jsonb_typeof(p_metadata) = 'array' THEN
    FOR metadata_value IN
      SELECT value FROM pg_catalog.jsonb_array_elements(p_metadata)
    LOOP
      IF jsonb_typeof(metadata_value) IN ('object', 'array')
        AND NOT kovcheg.event_metadata_is_sanitized(metadata_value)
      THEN
        RETURN false;
      END IF;
    END LOOP;
  END IF;

  RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.event_metadata_is_sanitized(jsonb) FROM PUBLIC;

ALTER TABLE kovcheg.outbox_events
  ADD CONSTRAINT outbox_events_sanitized_payload_check
  CHECK (kovcheg.event_metadata_is_sanitized(payload)) NOT VALID;
ALTER TABLE kovcheg.audit_events
  ADD CONSTRAINT audit_events_sanitized_details_check
  CHECK (kovcheg.event_metadata_is_sanitized(details)) NOT VALID;
ALTER TABLE kovcheg.operation_events
  ADD CONSTRAINT operation_events_sanitized_metadata_check
  CHECK (kovcheg.event_metadata_is_sanitized(metadata)) NOT VALID;

ALTER TABLE kovcheg.outbox_events
  VALIDATE CONSTRAINT outbox_events_sanitized_payload_check;
ALTER TABLE kovcheg.audit_events
  VALIDATE CONSTRAINT audit_events_sanitized_details_check;
ALTER TABLE kovcheg.operation_events
  VALIDATE CONSTRAINT operation_events_sanitized_metadata_check;

COMMENT ON COLUMN kovcheg.outbox_events.payload IS
  'Sanitized technical identifiers and counters only; no message text, identity/contact data, authentication material, credentials, or secrets.';
COMMENT ON COLUMN kovcheg.audit_events.details IS
  'Sanitized technical identifiers and counters only; no message text, identity/contact data, authentication material, credentials, or secrets.';
COMMENT ON COLUMN kovcheg.operation_events.metadata IS
  'Sanitized technical identifiers and counters only; no message text, identity/contact data, authentication material, credentials, or secrets.';

CREATE OR REPLACE FUNCTION kovcheg.assign_chat_sequence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, kovcheg
AS $$
DECLARE
  existing_fingerprint varchar(64);
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      NEW.chat_id::text || ':' || NEW.sender_account_id::text || ':' || NEW.client_idempotency_key,
      0
    )
  );

  SELECT content_fingerprint
  INTO existing_fingerprint
  FROM kovcheg.messages
  WHERE chat_id = NEW.chat_id
    AND sender_account_id = NEW.sender_account_id
    AND client_idempotency_key = NEW.client_idempotency_key;

  IF existing_fingerprint IS NOT NULL THEN
    IF existing_fingerprint = NEW.content_fingerprint THEN
      RETURN NULL;
    END IF;
    RAISE EXCEPTION 'idempotency key was reused with different content'
      USING ERRCODE = '23505', CONSTRAINT = 'messages_idempotency_unique';
  END IF;

  IF NOT kovcheg.can_account_post_to_chat(NEW.sender_account_id, NEW.chat_id) THEN
    RAISE EXCEPTION 'account cannot post to chat' USING ERRCODE = '42501';
  END IF;

  NEW.chat_sequence := kovcheg.allocate_chat_sequence(NEW.chat_id);
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION kovcheg.assign_chat_sequence() FROM PUBLIC;

INSERT INTO kovcheg.account_platform_roles (account_id, role) VALUES
  ('00000000-0000-4000-8000-000000001001', 'master'),
  ('00000000-0000-4000-8000-000000001002', 'warrior'),
  ('00000000-0000-4000-8000-000000001003', 'platform_administrator');

UPDATE kovcheg.chats
SET audience_kind = 'all_active_accounts'
WHERE id = '00000000-0000-4000-8000-000000001201';

UPDATE kovcheg.chat_memberships
SET is_administrator = true
WHERE chat_id = '00000000-0000-4000-8000-000000001201'
  AND account_id = '00000000-0000-4000-8000-000000001001';

INSERT INTO kovcheg.chat_service_labels (
  chat_id,
  label,
  assigned_by_account_id
) VALUES (
  '00000000-0000-4000-8000-000000001201',
  'primary',
  '00000000-0000-4000-8000-000000001001'
);

GRANT USAGE ON TYPE
  kovcheg.platform_role,
  kovcheg.chat_audience_kind,
  kovcheg.chat_posting_policy,
  kovcheg.chat_service_label
TO kovcheg_runtime;

GRANT SELECT ON
  kovcheg.account_platform_roles,
  kovcheg.chat_allowed_posting_roles,
  kovcheg.chat_service_labels,
  kovcheg.chat_membership_periods
TO kovcheg_runtime;

GRANT EXECUTE ON FUNCTION
  kovcheg.account_has_platform_role(uuid, kovcheg.platform_role),
  kovcheg.can_account_read_chat(uuid, uuid),
  kovcheg.can_account_post_to_chat(uuid, uuid),
  kovcheg.can_account_manage_chat_members(uuid, uuid),
  kovcheg.can_account_assign_chat_labels(uuid, uuid),
  kovcheg.event_metadata_is_sanitized(jsonb)
TO kovcheg_runtime;

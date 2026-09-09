-- Session-local helpers only: no migration, persistent function, or new grant.
CREATE FUNCTION pg_temp.owner_binding_state(owner_id uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, kovcheg AS $$
  SELECT jsonb_build_object(
    'account', (SELECT to_jsonb(a) FROM kovcheg.accounts a WHERE id = owner_id),
    'owner', (SELECT to_jsonb(o) FROM kovcheg.server_owner o WHERE account_id = owner_id),
    'bootstrap', (SELECT to_jsonb(b) FROM kovcheg.auth_administrator_bootstraps b WHERE account_id = owner_id),
    'profile', (SELECT to_jsonb(p) - ARRAY['email', 'display_name', 'updated_at'] FROM kovcheg.account_auth_profiles p WHERE account_id = owner_id),
    'domain', (SELECT to_jsonb(d) FROM kovcheg.account_domain_statuses d WHERE account_id = owner_id),
    'grants', (SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY role), '[]') FROM kovcheg.account_platform_roles r WHERE account_id = owner_id),
    'operatorGrants', (SELECT COALESCE(jsonb_agg(to_jsonb(g) ORDER BY persona_account_id), '[]') FROM kovcheg.system_persona_operator_grants g WHERE operator_account_id = owner_id),
    'memberships', (SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY chat_id), '[]') FROM kovcheg.chat_memberships m WHERE account_id = owner_id)
  );
$$;

CREATE TEMP TABLE owner_binding_result (outcome text NOT NULL);

DO $$
DECLARE
  input jsonb;
  baseline jsonb;
  desired jsonb;
  config jsonb;
  owner_id uuid;
  correlation text;
  unchanged_state jsonb;
  audit_id uuid;
  profile kovcheg.account_auth_profiles%ROWTYPE;
  previous_event kovcheg.audit_events%ROWTYPE;
  initialization_event_id uuid;
  grant_names jsonb;
  changed_count integer;
BEGIN
  IF session_user <> 'kovcheg_migrator' OR current_user <> 'kovcheg_migration'
    OR kovcheg.current_migration_version() IS DISTINCT FROM '0017' THEN
    RAISE EXCEPTION 'rejected';
  END IF;
  IF (SELECT count(*) FROM owner_binding_input) <> 1 THEN
    RAISE EXCEPTION 'rejected';
  END IF;
  SELECT convert_from(decode(encoded, 'base64'), 'UTF8')::jsonb INTO STRICT input
  FROM owner_binding_input WHERE octet_length(decode(encoded, 'base64')) <= 16384;
  IF jsonb_typeof(input) IS DISTINCT FROM 'object'
    OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(input) k)
      IS DISTINCT FROM ARRAY['expectedBootstrap','expectedDomainStatus','expectedFunctionalGrants','operationId','replacementBootstrap'] THEN
    RAISE EXCEPTION 'rejected';
  END IF;
  baseline := input->'expectedBootstrap';
  desired := input->'replacementBootstrap';
  FOREACH config IN ARRAY ARRAY[baseline, desired] LOOP
    IF jsonb_typeof(config) IS DISTINCT FROM 'object'
      OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(config) k)
        IS DISTINCT FROM ARRAY['bootstrapId','displayName','email','userId']
      OR EXISTS (SELECT 1 FROM jsonb_each(config) e WHERE jsonb_typeof(e.value) <> 'string')
      OR config->>'userId' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      OR config->>'bootstrapId' <> btrim(config->>'bootstrapId')
      OR char_length(config->>'bootstrapId') NOT BETWEEN 16 AND 200
      OR config->>'email' <> lower(btrim(config->>'email'))
      OR char_length(config->>'email') NOT BETWEEN 3 AND 254
      OR config->>'email' !~ '^[^[:space:]@]+@[^[:space:]@]+$'
      OR config->>'displayName' <> btrim(config->>'displayName')
      OR char_length(config->>'displayName') NOT BETWEEN 1 AND 120
      OR config->>'displayName' ~ '[[:cntrl:]]' THEN
      RAISE EXCEPTION 'rejected';
    END IF;
  END LOOP;
  IF baseline->>'userId' IS DISTINCT FROM desired->>'userId'
    OR baseline->>'bootstrapId' IS DISTINCT FROM desired->>'bootstrapId'
    OR baseline->>'email' = desired->>'email'
    OR split_part(baseline->>'email', '@', 2) !~ '(^|\.)(invalid|test|example|localhost)$|^example\.(com|net|org)$'
    OR jsonb_typeof(input->'operationId') IS DISTINCT FROM 'string'
    OR input->>'operationId' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    OR jsonb_typeof(input->'expectedDomainStatus') IS DISTINCT FROM 'string'
    OR jsonb_typeof(input->'expectedFunctionalGrants') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'rejected';
  END IF;
  owner_id := (baseline->>'userId')::uuid;
  correlation := 'initial-owner-binding:' || (input->>'operationId');

  -- Same ordering as ordinary bootstrap, followed by bounded write exclusion.
  PERFORM pg_advisory_xact_lock(hashtextextended('kovcheg.server-owner-bootstrap', 0));
  PERFORM pg_advisory_xact_lock(hashtextextended(baseline->>'bootstrapId', 0));
  LOCK TABLE kovcheg.accounts, kovcheg.account_auth_profiles,
    kovcheg.auth_administrator_bootstraps, kovcheg.server_owner,
    kovcheg.account_domain_statuses, kovcheg.account_platform_roles,
    kovcheg.chat_memberships, kovcheg.system_persona_operator_grants,
    kovcheg.auth_sessions, kovcheg.auth_email_challenges,
    kovcheg.auth_personal_gate_families, kovcheg.auth_personal_gate_sessions,
    kovcheg.auth_passkey_credentials, kovcheg.auth_passkey_assertion_evidence,
    kovcheg.oidc_provider_artifacts, kovcheg.chat_read_states, kovcheg.audit_events
    IN SHARE ROW EXCLUSIVE MODE;

  SELECT * INTO STRICT profile FROM kovcheg.account_auth_profiles WHERE account_id = owner_id;
  SELECT COALESCE(jsonb_agg(role::text ORDER BY role::text), '[]') INTO grant_names
  FROM kovcheg.account_platform_roles WHERE account_id = owner_id;
  IF (SELECT count(*) FROM kovcheg.account_auth_profiles) <> 1
    OR (SELECT count(*) FROM kovcheg.auth_administrator_bootstraps) <> 1
    OR (SELECT count(*) FROM kovcheg.server_owner) <> 1
    OR NOT EXISTS (SELECT 1 FROM kovcheg.server_owner WHERE account_id = owner_id AND singleton)
    OR NOT EXISTS (SELECT 1 FROM kovcheg.auth_administrator_bootstraps
      WHERE account_id = owner_id AND bootstrap_id = baseline->>'bootstrapId')
    OR NOT EXISTS (SELECT 1 FROM kovcheg.accounts WHERE id = owner_id AND kind = 'person' AND status = 'active')
    OR profile.auth_role <> 'administrator'
    OR NOT EXISTS (SELECT 1 FROM kovcheg.account_domain_statuses
      WHERE account_id = owner_id AND domain_status::text = input->>'expectedDomainStatus')
    OR grant_names IS DISTINCT FROM input->'expectedFunctionalGrants'
    OR NOT grant_names @> '["platform_administrator"]'::jsonb
    OR EXISTS (SELECT 1 FROM kovcheg.account_auth_profiles WHERE email = desired->>'email' AND account_id <> owner_id) THEN
    RAISE EXCEPTION 'rejected';
  END IF;

  -- Ordinary bootstrap itself creates exactly one account.provisioned event.
  -- Match its full public semantics, including creation-time ordering and the
  -- starter set count; do not treat arbitrary system/owner audit as initialization.
  SELECT event.id INTO STRICT initialization_event_id
  FROM kovcheg.audit_events event
  JOIN kovcheg.accounts account ON account.id = owner_id
  WHERE event.actor_account_id = owner_id AND event.target_id = owner_id
    AND event.action = 'account.provisioned' AND event.target_type = 'account'
    AND event.correlation_id = 'auth-bootstrap-' || owner_id::text
    AND event.migration_version = '0017' AND event.outcome = 'success'
    AND event.occurred_at >= account.created_at AND event.occurred_at <= profile.created_at
    AND event.details = jsonb_build_object('starterChatCount',
      (SELECT count(*) FROM kovcheg.chat_memberships WHERE account_id = owner_id AND status = 'active'));

  -- Count expired/revoked state too. Unattributable OIDC state fails closed;
  -- this initial, singleton-profile operation never deletes it to obtain PASS.
  IF EXISTS (SELECT 1 FROM kovcheg.auth_sessions WHERE account_id = owner_id)
    OR EXISTS (SELECT 1 FROM kovcheg.auth_email_challenges WHERE account_id = owner_id)
    OR EXISTS (SELECT 1 FROM kovcheg.auth_personal_gate_families WHERE account_id = owner_id)
    OR EXISTS (SELECT 1 FROM kovcheg.auth_personal_gate_sessions WHERE account_id = owner_id)
    OR EXISTS (SELECT 1 FROM kovcheg.auth_passkey_credentials WHERE account_id = owner_id)
    OR EXISTS (SELECT 1 FROM kovcheg.auth_passkey_assertion_evidence WHERE account_id = owner_id)
    OR EXISTS (SELECT 1 FROM kovcheg.oidc_provider_artifacts)
    OR EXISTS (SELECT 1 FROM kovcheg.chat_read_states WHERE account_id = owner_id)
    OR EXISTS (SELECT 1 FROM kovcheg.audit_events WHERE
      (actor_account_id = owner_id OR target_id = owner_id)
      AND id <> initialization_event_id AND correlation_id <> correlation) THEN
    RAISE EXCEPTION 'rejected';
  END IF;

  SELECT * INTO previous_event FROM kovcheg.audit_events WHERE correlation_id = correlation;
  IF FOUND THEN
    IF (SELECT count(*) FROM kovcheg.audit_events WHERE correlation_id = correlation) <> 1
      OR previous_event.actor_account_id IS NOT NULL
      OR previous_event.action <> 'auth.account.updated'
      OR previous_event.target_type <> 'auth_account'
      OR previous_event.target_id IS DISTINCT FROM owner_id
      OR previous_event.outcome <> 'success' OR previous_event.details <> '{}'::jsonb
      OR profile.email <> desired->>'email' OR profile.display_name <> desired->>'displayName' THEN
      RAISE EXCEPTION 'rejected';
    END IF;
    INSERT INTO owner_binding_result VALUES ('ALREADY_BOUND');
    RETURN;
  END IF;
  IF profile.email <> baseline->>'email' OR profile.display_name <> baseline->>'displayName' THEN
    RAISE EXCEPTION 'rejected';
  END IF;
  unchanged_state := pg_temp.owner_binding_state(owner_id);
  UPDATE kovcheg.account_auth_profiles
  SET email = desired->>'email', display_name = desired->>'displayName', updated_at = clock_timestamp()
  WHERE account_id = owner_id;
  GET DIAGNOSTICS changed_count = ROW_COUNT;
  IF changed_count <> 1 OR unchanged_state IS DISTINCT FROM pg_temp.owner_binding_state(owner_id)
    OR NOT EXISTS (SELECT 1 FROM kovcheg.account_auth_profiles WHERE account_id = owner_id
      AND email = desired->>'email' AND display_name = desired->>'displayName') THEN
    RAISE EXCEPTION 'rejected';
  END IF;
  audit_id := kovcheg.append_audit_event(correlation::varchar,
    kovcheg.current_migration_version()::varchar, NULL, 'auth.account.updated'::varchar,
    'auth_account'::varchar, owner_id, 'success', '{}'::jsonb);
  IF NOT EXISTS (SELECT 1 FROM kovcheg.audit_events WHERE id = audit_id
    AND correlation_id = correlation AND actor_account_id IS NULL
    AND action = 'auth.account.updated' AND target_type = 'auth_account'
    AND target_id = owner_id AND outcome = 'success' AND details = '{}'::jsonb)
    OR (SELECT count(*) FROM kovcheg.audit_events WHERE correlation_id = correlation) <> 1
    OR unchanged_state IS DISTINCT FROM pg_temp.owner_binding_state(owner_id)
    OR NOT EXISTS (SELECT 1 FROM kovcheg.account_auth_profiles WHERE account_id = owner_id
      AND email = desired->>'email' AND display_name = desired->>'displayName') THEN
    RAISE EXCEPTION 'rejected';
  END IF;
  INSERT INTO owner_binding_result VALUES ('BOUND');
EXCEPTION WHEN OTHERS THEN
  -- No SQLERRM, DETAIL, parameters, or private contact data in the error.
  RAISE EXCEPTION 'initial owner binding rejected' USING ERRCODE = 'P0001';
END;
$$;

COMMIT;
SELECT outcome FROM owner_binding_result;

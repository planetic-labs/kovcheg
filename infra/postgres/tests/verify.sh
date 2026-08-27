#!/bin/sh

set -eu

test_root=/workspace/infra/postgres/tests
scenario=${TEST_SCENARIO:-clean}

read_secret() {
  secret_value=$(tr -d '\r\n' <"$1")
  if [ -z "$secret_value" ]; then
    echo 'A PostgreSQL test secret is empty.' >&2
    exit 1
  fi
  printf '%s' "$secret_value"
}

superuser_password=$(read_secret /run/secrets/postgres_superuser_password)
migration_password=$(read_secret /run/secrets/postgres_migration_password)
runtime_password=$(read_secret /run/secrets/postgres_runtime_password)
audit_password=$(read_secret /run/secrets/postgres_audit_password)
auth_password=$(read_secret /run/secrets/postgres_auth_password)

run_sql() {
  role=$1
  password=$2
  sql_file=$3
  PGPASSWORD="$password" psql --no-psqlrc --set=ON_ERROR_STOP=1 \
    --username "$role" --file "$sql_file"
}

query_as_runtime() {
  PGPASSWORD="$runtime_password" psql --no-psqlrc --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --username kovcheg_app --command "$1"
}

query_as_migration() {
  PGPASSWORD="$migration_password" psql --no-psqlrc --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --username kovcheg_migrator --command "$1"
}

wait_for_application_lock() {
  application_name=$1
  lock_id=$2
  lock_granted=$3

  query_as_migration "
    DO \$\$
    DECLARE
      attempt integer := 0;
    BEGIN
      LOOP
        PERFORM pg_catalog.pg_stat_clear_snapshot();
        IF EXISTS (
          SELECT 1
          FROM pg_catalog.pg_locks AS held_lock
          JOIN pg_catalog.pg_stat_activity AS activity
            ON activity.pid = held_lock.pid
          WHERE activity.application_name = '$application_name'
            AND held_lock.locktype = 'advisory'
            AND held_lock.objid = $lock_id
            AND held_lock.granted IS $lock_granted
        ) THEN
          RETURN;
        END IF;

        attempt := attempt + 1;
        IF attempt > 1000000 THEN
          RAISE EXCEPTION 'deterministic race barrier was not reached';
        END IF;
      END LOOP;
    END;
    \$\$;
  " >/dev/null
}

wait_for_application_row_lock() {
  application_name=$1

  query_as_migration "
    DO \$\$
    DECLARE
      attempt integer := 0;
    BEGIN
      LOOP
        PERFORM pg_catalog.pg_stat_clear_snapshot();
        IF EXISTS (
          SELECT 1
          FROM pg_catalog.pg_locks AS waiting_lock
          JOIN pg_catalog.pg_stat_activity AS activity
            ON activity.pid = waiting_lock.pid
          WHERE activity.application_name = '$application_name'
            AND NOT waiting_lock.granted
        ) THEN
          RETURN;
        END IF;

        attempt := attempt + 1;
        IF attempt > 1000000 THEN
          RAISE EXCEPTION 'concurrent authorization mutation did not wait for the action';
        END IF;
      END LOOP;
    END;
    \$\$;
  " >/dev/null
}

message_audit_enabled=false

run_message_creation_as_runtime() {
  message_chat_id=$1
  message_key=$2
  message_fingerprint=$3
  message_body=$4
  message_correlation_id=$5

  if [ "$message_audit_enabled" = true ]; then
    PGPASSWORD="$runtime_password" psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --username kovcheg_app --command="
        SELECT * FROM kovcheg.create_text_message_for_session(
          '$message_chat_id',
          '00000000-0000-4000-8000-000000002201',
          '00000000-0000-4000-8000-000000002001',
          NULL,
          '$message_key',
          '$message_fingerprint',
          '$message_body',
          '$message_correlation_id',
          '2030-01-01 00:30:00+00'
        )
      "
  else
    PGPASSWORD="$runtime_password" psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --username kovcheg_app --command="
        SELECT * FROM kovcheg.create_text_message(
          '$message_chat_id',
          '00000000-0000-4000-8000-000000002001',
          '$message_key',
          '$message_fingerprint',
          '$message_body',
          '$message_correlation_id'
        )
      "
  fi
}

verify_latest_migration_state() {
  latest_state=$(
    query_as_migration "
      SELECT kovcheg.current_migration_version() || ':' || count(*)
      FROM kovcheg_meta.schema_migrations
    "
  )
  if [ "$latest_state" != '0014:14' ]; then
    echo 'The complete fourteen-migration chain was not recorded.' >&2
    exit 1
  fi
}

run_parallel_sequence_test() {
  parallel_chat_id=$(
    query_as_runtime "SELECT id FROM kovcheg.chats WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001' ORDER BY id LIMIT 1"
  )
  if [ -z "$parallel_chat_id" ]; then
    echo 'A provisioned direct chat is required for the sequence test.' >&2
    exit 1
  fi

  parallel_number=1
  parallel_pids=''
  while [ "$parallel_number" -le 12 ]; do
    PGPASSWORD="$runtime_password" psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --username kovcheg_app --command="
        INSERT INTO kovcheg.messages (
          chat_id,
          sender_account_id,
          client_idempotency_key,
          content_fingerprint,
          body,
          correlation_id
        ) VALUES (
          '$parallel_chat_id',
          '00000000-0000-4000-8000-000000002001',
          'parallel-$parallel_number',
          'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
          'Synthetic parallel message',
          'database-parallel-$parallel_number'
        )
      " >/dev/null &
    parallel_pids="$parallel_pids $!"
    parallel_number=$((parallel_number + 1))
  done

  for parallel_pid in $parallel_pids; do
    wait "$parallel_pid"
  done
}

run_message_flow_race_test() {
  parallel_chat_id=$(
    query_as_runtime "SELECT id FROM kovcheg.chats WHERE provisioned_for_account_id = '00000000-0000-4000-8000-000000002001' ORDER BY id LIMIT 1"
  )
  counter_before=$(
    query_as_migration "SELECT next_sequence FROM kovcheg.chat_counters WHERE chat_id = '$parallel_chat_id'"
  )

  parallel_number=1
  parallel_pids=''
  while [ "$parallel_number" -le 12 ]; do
    run_message_creation_as_runtime \
      "$parallel_chat_id" \
      'message-flow-race-001' \
      'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' \
      'Synthetic concurrent retry' \
      "database-message-flow-race-$parallel_number" >/dev/null &
    parallel_pids="$parallel_pids $!"
    parallel_number=$((parallel_number + 1))
  done

  for parallel_pid in $parallel_pids; do
    wait "$parallel_pid"
  done

  race_state=$(
    query_as_migration "
      SELECT
        (SELECT count(*) FROM kovcheg.messages WHERE chat_id = '$parallel_chat_id' AND client_idempotency_key = 'message-flow-race-001') || ':' ||
        (SELECT next_sequence - $counter_before FROM kovcheg.chat_counters WHERE chat_id = '$parallel_chat_id') || ':' ||
        (SELECT count(*) FROM kovcheg.outbox_events WHERE correlation_id LIKE 'database-message-flow-race-%')
    "
  )
  if [ "$race_state" != '1:1:1' ]; then
    echo 'Concurrent identical retries did not preserve one message, sequence, and outbox event.' >&2
    exit 1
  fi

  counter_before=$(
    query_as_migration "SELECT next_sequence FROM kovcheg.chat_counters WHERE chat_id = '$parallel_chat_id'"
  )
  parallel_number=1
  parallel_pids=''
  while [ "$parallel_number" -le 12 ]; do
    run_message_creation_as_runtime \
      "$parallel_chat_id" \
      "message-flow-parallel-$parallel_number" \
      'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' \
      "Synthetic parallel message $parallel_number" \
      "database-message-flow-parallel-$parallel_number" >/dev/null &
    parallel_pids="$parallel_pids $!"
    parallel_number=$((parallel_number + 1))
  done

  for parallel_pid in $parallel_pids; do
    wait "$parallel_pid"
  done

  sequence_state=$(
    query_as_migration "
      SELECT
        count(*) || ':' ||
        (max(chat_sequence) - min(chat_sequence) + 1) || ':' ||
        (SELECT next_sequence - $counter_before FROM kovcheg.chat_counters WHERE chat_id = '$parallel_chat_id')
      FROM kovcheg.messages
      WHERE chat_id = '$parallel_chat_id'
        AND client_idempotency_key LIKE 'message-flow-parallel-%'
    "
  )
  if [ "$sequence_state" != '12:12:12' ]; then
    echo 'Concurrent distinct sends did not preserve a gap-free chat-local sequence.' >&2
    exit 1
  fi
}

run_core_tests() {
  run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
  run_sql kovcheg_migrator "$migration_password" "$test_root/verify-core.sql"
  run_sql kovcheg_app "$runtime_password" "$test_root/verify-runtime.sql"
  run_sql kovcheg_audit_writer "$audit_password" "$test_root/verify-audit-writer.sql"
  run_parallel_sequence_test
  run_sql kovcheg_migrator "$migration_password" "$test_root/verify-state-and-plans.sql"
}

run_message_flow_tests() {
  if [ "$(query_as_migration "
    SELECT to_regprocedure(
      'kovcheg.create_text_message_for_session(uuid,uuid,uuid,uuid,character varying,character varying,text,character varying,timestamp with time zone)'
    ) IS NOT NULL
  ")" = t ]; then
    message_audit_enabled=true
  else
    message_audit_enabled=false
  fi

  run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
  run_sql kovcheg_migrator "$migration_password" "$test_root/verify-core.sql"
  if [ "$message_audit_enabled" = true ]; then
    run_sql kovcheg_migrator "$migration_password" \
      "$test_root/verify-message-flow-session-fixture.sql"
  fi
  run_sql kovcheg_app "$runtime_password" "$test_root/verify-message-flow.sql"
  run_message_flow_race_test
  run_sql kovcheg_migrator "$migration_password" "$test_root/verify-message-flow-authorization.sql"
  run_sql kovcheg_audit_writer "$audit_password" "$test_root/verify-audit-writer.sql"
  run_sql kovcheg_migrator "$migration_password" "$test_root/verify-state-and-plans.sql"
}

run_auth_tests() {
  run_sql kovcheg_auth_app "$auth_password" "$test_root/verify-auth-runtime.sql"
  run_sql kovcheg_auth_app "$auth_password" \
    "$test_root/verify-auth-personal-entry-gate.sql"

  gate_race_result_root="/tmp/kovcheg-gate-race-$$"
  parallel_number=1
  parallel_pids=''
  while [ "$parallel_number" -le 12 ]; do
    PGPASSWORD="$auth_password" psql --no-psqlrc --tuples-only --no-align --quiet \
      --set=ON_ERROR_STOP=1 --username kovcheg_auth_app --command="
        SELECT outcome || ':' || reused
        FROM kovcheg.activate_auth_personal_gate(
          repeat('R', 43),
          '00000000-0000-4000-8000-000000004210',
          repeat('S', 43),
          'synthetic-client-race-001',
          '2030-01-01 00:56:02+00',
          'gate-race-activate'
        )
      " >"$gate_race_result_root-$parallel_number" &
    parallel_pids="$parallel_pids $!"
    parallel_number=$((parallel_number + 1))
  done

  for parallel_pid in $parallel_pids; do
    wait "$parallel_pid"
  done

  race_active_count=$(grep -h -c '^active:' "$gate_race_result_root"-* | awk '{ total += $1 } END { print total + 0 }')
  if [ "$race_active_count" -ne 12 ]; then
    echo 'Concurrent gate activation did not return twelve successful idempotent outcomes.' >&2
    exit 1
  fi

  gate_race_state=$(query_as_migration "
    SELECT
      (SELECT count(*)
       FROM kovcheg.auth_personal_gate_sessions
       WHERE family_id = '00000000-0000-4000-8000-000000004110'
         AND client_idempotency_key = 'synthetic-client-race-001') || ':' ||
      (SELECT count(*)
       FROM kovcheg.audit_events
       WHERE correlation_id = 'gate-race-activate')
  ")
  if [ "$gate_race_state" != '1:1' ]; then
    echo 'Concurrent gate activation did not preserve one session and one audit event.' >&2
    exit 1
  fi

  run_sql kovcheg_migrator "$migration_password" \
    "$test_root/verify-auth-personal-entry-gate-owner.sql"

  parallel_number=1
  parallel_pids=''
  while [ "$parallel_number" -le 12 ]; do
    session_suffix=$(printf '%012d' "$parallel_number")
    PGPASSWORD="$auth_password" psql --no-psqlrc --tuples-only --no-align --quiet \
      --set=ON_ERROR_STOP=1 --username kovcheg_auth_app --command="
        SELECT outcome
        FROM kovcheg.consume_auth_challenge_and_create_session(
          '00000000-0000-4000-8000-000000003109',
          repeat('k', 43),
          '2030-01-01 00:20:01+00',
          '00000000-0000-4000-8001-$session_suffix',
          lpad('$parallel_number', 43, 'p'),
          '2030-01-01 00:20:01+00',
          60000,
          '2030-01-01 00:30:01+00'
        )
      " >"/tmp/kovcheg-auth-result-$parallel_number" &
    parallel_pids="$parallel_pids $!"
    parallel_number=$((parallel_number + 1))
  done

  for parallel_pid in $parallel_pids; do
    wait "$parallel_pid"
  done

  authenticated_count=$(grep -h -c '^authenticated$' /tmp/kovcheg-auth-result-* | awk '{ total += $1 } END { print total + 0 }')
  invalid_count=$(grep -h -c '^invalid$' /tmp/kovcheg-auth-result-* | awk '{ total += $1 } END { print total + 0 }')
  if [ "$authenticated_count" -ne 1 ] || [ "$invalid_count" -ne 11 ]; then
    echo 'Concurrent challenge verification did not produce exactly one session.' >&2
    exit 1
  fi
  find /tmp -maxdepth 1 -name 'kovcheg-auth-result-*' -type f -delete

  parallel_number=1
  parallel_pids=''
  while [ "$parallel_number" -le 12 ]; do
    PGPASSWORD="$auth_password" psql --no-psqlrc --tuples-only --no-align --quiet \
      --set=ON_ERROR_STOP=1 --username kovcheg_auth_app --command="
        SELECT kovcheg.admin_revoke_all_auth_sessions(
          repeat('m', 43),
          '00000000-0000-4000-8000-000000003005',
          '2030-01-01 00:20:30+00',
          'auth-admin-revoke-all-race-$parallel_number'
        )
      " >"/tmp/kovcheg-auth-admin-result-$parallel_number" &
    parallel_pids="$parallel_pids $!"
    parallel_number=$((parallel_number + 1))
  done

  for parallel_pid in $parallel_pids; do
    wait "$parallel_pid"
  done

  revoked_total=$(awk '{ total += $1 } END { print total + 0 }' /tmp/kovcheg-auth-admin-result-*)
  effective_calls=$(awk '$1 > 0 { total += 1 } END { print total + 0 }' /tmp/kovcheg-auth-admin-result-*)
  zero_calls=$(grep -h -c '^0$' /tmp/kovcheg-auth-admin-result-* | awk '{ total += $1 } END { print total + 0 }')
  if [ "$revoked_total" -ne 12 ] || [ "$effective_calls" -ne 1 ] || [ "$zero_calls" -ne 11 ]; then
    echo 'Concurrent revoke-all retries did not revoke the target sessions exactly once.' >&2
    exit 1
  fi
  find /tmp -maxdepth 1 -name 'kovcheg-auth-admin-result-*' -type f -delete

  remaining_target_sessions=$(
    query_as_migration "
      SELECT count(*)
      FROM kovcheg.auth_sessions
      WHERE account_id = '00000000-0000-4000-8000-000000003005'
        AND revoked_at IS NULL
    "
  )
  if [ "$remaining_target_sessions" -ne 0 ]; then
    echo 'Concurrent revoke-all left an unrevoked target session.' >&2
    exit 1
  fi

  run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
}

run_persona_message_race() {
  race_name=$1
  operator_account_id=$2
  persona_account_id=$3
  session_id=$4
  chat_id=$5
  lock_base=$6
  mutation_role=$7
  mutation_sql=$8

  ready_lock=$((lock_base + 1))
  gate_lock=$((lock_base + 2))
  gate_application="persona-race-gate-$race_name"
  action_application="persona-race-action-$race_name"
  mutation_application="persona-race-mutation-$race_name"
  gate_fifo="/tmp/kovcheg-persona-race-$race_name-$$.fifo"
  gate_output="/tmp/kovcheg-persona-race-$race_name-$$-gate.log"
  action_output="/tmp/kovcheg-persona-race-$race_name-$$-action.log"
  mutation_output="/tmp/kovcheg-persona-race-$race_name-$$-mutation.log"
  denied_output="/tmp/kovcheg-persona-race-$race_name-$$-denied.log"

  mkfifo "$gate_fifo"
  PGAPPNAME="$gate_application" PGPASSWORD="$migration_password" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --username kovcheg_migrator \
    <"$gate_fifo" >"$gate_output" 2>&1 &
  gate_pid=$!
  exec 9>"$gate_fifo"
  printf 'SELECT pg_advisory_lock(%s);\n' "$gate_lock" >&9
  wait_for_application_lock "$gate_application" "$gate_lock" true

  PGAPPNAME="$action_application" PGPASSWORD="$runtime_password" \
    psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --username kovcheg_app --command="
      BEGIN;
      SELECT * FROM kovcheg.authorize_system_persona_action(
        '$session_id',
        '$operator_account_id',
        '$persona_account_id',
        '2030-01-01 00:30:00+00'
      );
      SELECT pg_advisory_lock($ready_lock);
      SELECT pg_advisory_lock($gate_lock);
      SELECT * FROM kovcheg.create_text_message_for_session(
        '$chat_id',
        '$session_id',
        '$operator_account_id',
        '$persona_account_id',
        'privacy-race-$race_name-before',
        repeat('e', 64),
        'Synthetic privacy race message',
        'privacy-race-$race_name-before',
        '2030-01-01 00:30:00+00'
      );
      COMMIT;
    " >"$action_output" 2>&1 &
  action_pid=$!
  wait_for_application_lock "$action_application" "$ready_lock" true

  if [ "$mutation_role" = auth ]; then
    PGAPPNAME="$mutation_application" PGPASSWORD="$auth_password" \
      psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --username kovcheg_auth_app \
      --command="$mutation_sql" >"$mutation_output" 2>&1 &
  else
    PGAPPNAME="$mutation_application" PGPASSWORD="$migration_password" \
      psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --username kovcheg_migrator \
      --command="$mutation_sql" >"$mutation_output" 2>&1 &
  fi
  mutation_pid=$!
  wait_for_application_row_lock "$mutation_application"

  printf 'SELECT pg_advisory_unlock(%s);\n' "$gate_lock" >&9
  if ! wait "$action_pid"; then
    sed -n '1,120p' "$action_output" >&2
    echo "The authorization-first $race_name action failed." >&2
    exit 1
  fi
  if ! wait "$mutation_pid"; then
    sed -n '1,120p' "$mutation_output" >&2
    echo "The concurrent $race_name mutation failed." >&2
    exit 1
  fi
  exec 9>&-
  if ! wait "$gate_pid"; then
    sed -n '1,120p' "$gate_output" >&2
    echo "The $race_name barrier session failed." >&2
    exit 1
  fi

  if PGPASSWORD="$runtime_password" psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
    --username kovcheg_app --command="
      SELECT * FROM kovcheg.create_text_message_for_session(
        '$chat_id',
        '$session_id',
        '$operator_account_id',
        '$persona_account_id',
        'privacy-race-$race_name-after',
        repeat('f', 64),
        'Synthetic denied privacy race message',
        'privacy-race-$race_name-after',
        '2030-01-01 00:41:00+00'
      );
    " >"$denied_output" 2>&1; then
    echo "The post-mutation $race_name action was authorized." >&2
    exit 1
  fi
  if ! grep -q 'persona authorization failed' "$denied_output"; then
    sed -n '1,120p' "$denied_output" >&2
    echo "The post-mutation $race_name failure was not neutral." >&2
    exit 1
  fi

  rm -f "$gate_fifo" "$gate_output" "$action_output" "$mutation_output" "$denied_output"
}

run_persona_privacy_race_tests() {
  run_sql kovcheg_migrator "$migration_password" \
    "$test_root/verify-persona-privacy-race-fixtures.sql"

  run_persona_message_race \
    grant \
    '00000000-0000-4000-8000-000000009011' \
    '00000000-0000-4000-8000-000000009111' \
    '00000000-0000-4000-8000-000000009211' \
    '00000000-0000-4000-8000-000000009411' \
    781100 \
    auth \
    "SELECT kovcheg.admin_revoke_system_persona_operator(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000009011',
      '00000000-0000-4000-8000-000000009111',
      '2030-01-01 00:40:00+00',
      'privacy-race-grant-mutation'
    )"

  run_persona_message_race \
    operator \
    '00000000-0000-4000-8000-000000009012' \
    '00000000-0000-4000-8000-000000009112' \
    '00000000-0000-4000-8000-000000009212' \
    '00000000-0000-4000-8000-000000009412' \
    781200 \
    auth \
    "SELECT * FROM kovcheg.admin_set_auth_account_status(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000009012',
      'deactivated',
      '2030-01-01 00:40:00+00',
      'privacy-race-operator-mutation'
    )"

  run_persona_message_race \
    persona \
    '00000000-0000-4000-8000-000000009013' \
    '00000000-0000-4000-8000-000000009113' \
    '00000000-0000-4000-8000-000000009213' \
    '00000000-0000-4000-8000-000000009413' \
    781300 \
    migration \
    "UPDATE kovcheg.accounts
     SET status = 'deactivated', deactivated_at = '2030-01-01 00:40:00+00'
     WHERE id = '00000000-0000-4000-8000-000000009113'"

  run_persona_message_race \
    session \
    '00000000-0000-4000-8000-000000009014' \
    '00000000-0000-4000-8000-000000009114' \
    '00000000-0000-4000-8000-000000009214' \
    '00000000-0000-4000-8000-000000009414' \
    781400 \
    auth \
    "SELECT kovcheg.admin_revoke_auth_session(
      repeat('m', 43),
      '00000000-0000-4000-8000-000000009014',
      '00000000-0000-4000-8000-000000009214',
      '2030-01-01 00:40:00+00',
      'privacy-race-session-mutation'
    )"

  run_sql kovcheg_migrator "$migration_password" \
    "$test_root/verify-persona-privacy-race.sql"
}

run_persona_authorization_tests() {
  run_sql kovcheg_migrator "$migration_password" \
    "$test_root/verify-persona-authorization-fixtures.sql"
  run_sql kovcheg_app "$runtime_password" \
    "$test_root/verify-persona-authorization-runtime.sql"
  run_persona_privacy_race_tests
  run_sql kovcheg_migrator "$migration_password" \
    "$test_root/revoke-persona-authorization-fixture.sql"
  run_sql kovcheg_app "$runtime_password" \
    "$test_root/verify-persona-authorization-revocation.sql"
}

case "$scenario" in
  clean)
    run_message_flow_tests
    verify_latest_migration_state
    run_auth_tests
    run_sql kovcheg_migrator "$migration_password" \
      "$test_root/verify-server-role-capabilities.sql"
    run_sql kovcheg_migrator "$migration_password" \
      "$test_root/verify-role-administration-capabilities.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-persona-data-owner.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-query-plans.sql"
    run_persona_authorization_tests
    ;;
  persona-message-fixture)
    run_sql kovcheg_migrator "$migration_password" \
      "$test_root/verify-persona-authorization-fixtures.sql"
    ;;
  upgrade-v1)
    run_core_tests
    ;;
  upgrade-v2)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-v2.sql"
    run_sql kovcheg_app "$runtime_password" "$test_root/verify-runtime-claims.sql"
    ;;
  upgrade-v3)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-v3.sql"
    run_sql kovcheg_app "$runtime_password" "$test_root/verify-runtime-claims.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-state-and-plans.sql"
    ;;
  upgrade-v4)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-v4.sql"
    ;;
  upgrade-v5)
    run_message_flow_tests
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-latest.sql"
    ;;
  upgrade-v6)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-v6.sql"
    ;;
  upgrade-v7)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-v7.sql"
    ;;
  upgrade-v8)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-v8.sql"
    ;;
  upgrade-v9)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-v9.sql"
    ;;
  upgrade-v10)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-v10.sql"
    ;;
  upgrade-v11)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-v11.sql"
    ;;
  upgrade-v12)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-v12.sql"
    ;;
  upgrade-v13)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-v13.sql"
    ;;
  upgrade-latest)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    verify_latest_migration_state
    run_auth_tests
    run_sql kovcheg_migrator "$migration_password" \
      "$test_root/verify-server-role-capabilities.sql"
    run_sql kovcheg_migrator "$migration_password" \
      "$test_root/verify-role-administration-capabilities.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-persona-data-owner.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-query-plans.sql"
    run_persona_authorization_tests
    ;;
  *)
    echo 'Unknown database test scenario.' >&2
    exit 1
    ;;
esac

unset superuser_password migration_password runtime_password audit_password auth_password secret_value

echo "Database verification passed for scenario: $scenario."

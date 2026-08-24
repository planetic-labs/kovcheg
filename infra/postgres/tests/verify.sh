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

verify_latest_migration_state() {
  latest_state=$(
    query_as_migration "
      SELECT kovcheg.current_migration_version() || ':' || count(*)
      FROM kovcheg_meta.schema_migrations
    "
  )
  if [ "$latest_state" != '0008:8' ]; then
    echo 'The complete eight-migration chain was not recorded.' >&2
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
    PGPASSWORD="$runtime_password" psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --username kovcheg_app --command="
        SELECT * FROM kovcheg.create_text_message(
          '$parallel_chat_id',
          '00000000-0000-4000-8000-000000002001',
          'message-flow-race-001',
          'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
          'Synthetic concurrent retry',
          'database-message-flow-race-$parallel_number'
        )
      " >/dev/null &
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
    PGPASSWORD="$runtime_password" psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 \
      --username kovcheg_app --command="
        SELECT * FROM kovcheg.create_text_message(
          '$parallel_chat_id',
          '00000000-0000-4000-8000-000000002001',
          'message-flow-parallel-$parallel_number',
          'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
          'Synthetic parallel message $parallel_number',
          'database-message-flow-parallel-$parallel_number'
        )
      " >/dev/null &
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
  run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
  run_sql kovcheg_migrator "$migration_password" "$test_root/verify-core.sql"
  run_sql kovcheg_app "$runtime_password" "$test_root/verify-message-flow.sql"
  run_message_flow_race_test
  run_sql kovcheg_migrator "$migration_password" "$test_root/verify-message-flow-authorization.sql"
  run_sql kovcheg_audit_writer "$audit_password" "$test_root/verify-audit-writer.sql"
  run_sql kovcheg_migrator "$migration_password" "$test_root/verify-state-and-plans.sql"
}

run_auth_tests() {
  run_sql kovcheg_auth_app "$auth_password" "$test_root/verify-auth-runtime.sql"

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

case "$scenario" in
  clean)
    run_message_flow_tests
    verify_latest_migration_state
    run_auth_tests
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-persona-data-owner.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-query-plans.sql"
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
  upgrade-latest)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    verify_latest_migration_state
    run_auth_tests
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-persona-data-owner.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-query-plans.sql"
    ;;
  *)
    echo 'Unknown database test scenario.' >&2
    exit 1
    ;;
esac

unset superuser_password migration_password runtime_password audit_password auth_password secret_value

echo "Database verification passed for scenario: $scenario."

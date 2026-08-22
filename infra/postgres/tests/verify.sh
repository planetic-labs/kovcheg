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

run_core_tests() {
  run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
  run_sql kovcheg_migrator "$migration_password" "$test_root/verify-core.sql"
  run_sql kovcheg_app "$runtime_password" "$test_root/verify-runtime.sql"
  run_sql kovcheg_audit_writer "$audit_password" "$test_root/verify-audit-writer.sql"
  run_parallel_sequence_test
  run_sql kovcheg_migrator "$migration_password" "$test_root/verify-state-and-plans.sql"
}

case "$scenario" in
  clean)
    run_core_tests
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-latest.sql"
    ;;
  upgrade-v1)
    run_core_tests
    ;;
  upgrade-latest)
    run_sql postgres "$superuser_password" "$test_root/verify-security.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-latest.sql"
    run_sql kovcheg_migrator "$migration_password" "$test_root/verify-state-and-plans.sql"
    ;;
  *)
    echo 'Unknown database test scenario.' >&2
    exit 1
    ;;
esac

unset superuser_password migration_password runtime_password audit_password secret_value

echo "Database verification passed for scenario: $scenario."

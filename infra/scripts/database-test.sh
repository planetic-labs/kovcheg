#!/bin/sh

set -eu

. infra/scripts/docker-test-lifecycle.sh

mkdir -p "$PWD/.local"
test_root=$(mktemp -d "$PWD/.local/database-test.XXXXXX")
secret_root="$test_root/secrets"
base_project="kovcheg-db-$$"

docker_test_begin database-test "$base_project"
docker_test_configure_compose_images "kovcheg-test-database-$KOVCHEG_TEST_RUN_ID"
docker_storage_preflight

mkdir -p "$secret_root"
export KOVCHEG_LOCAL_SECRET_DIR="$secret_root"
export COMPOSE_PARALLEL_LIMIT=1

compose() {
  sh infra/scripts/compose.sh \
    --file compose.yaml \
    --file infra/testing/compose.lifecycle.yaml \
    "$@"
}

cleanup_project() {
  COMPOSE_PROJECT_NAME=$1 compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}

cleanup() {
  cleanup_status=$?
  lifecycle_status=0
  if [ "$cleanup_status" -ne 0 ]; then
    for failed_project in "${base_project}-clean" "${base_project}-upgrade"; do
      COMPOSE_PROJECT_NAME="$failed_project" compose ps --all || true
      COMPOSE_PROJECT_NAME="$failed_project" compose logs --no-color postgres || true
    done
  fi
  cleanup_project "${base_project}-clean"
  cleanup_project "${base_project}-upgrade"
  docker_test_finish || lifecycle_status=$?
  find "$test_root" -type f -delete
  find "$test_root" -depth -type d -empty -delete
  docker_test_remove_state
  if [ "$cleanup_status" -ne 0 ]; then
    return "$cleanup_status"
  fi
  return "$lifecycle_status"
}

trap cleanup EXIT INT TERM

run_clean_scenario() {
  export COMPOSE_PROJECT_NAME="${base_project}-clean"
  compose up --detach --wait postgres
  compose --profile data run --rm migrate
  compose --profile data run --rm -e TEST_SCENARIO=clean database-test
  compose --profile data run --rm message-flow-test
  compose --profile data run --rm auth-integration-test
  compose --profile data run --rm migrate
  cleanup_project "$COMPOSE_PROJECT_NAME"
}

run_upgrade_scenario() {
  export COMPOSE_PROJECT_NAME="${base_project}-upgrade"
  compose up --detach --wait postgres
  compose --profile data run --rm -e MIGRATION_TARGET=0001 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v1 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0002 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v2 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0003 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v3 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0004 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v4 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0005 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v5 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0006 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v6 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0007 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v7 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0008 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v8 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0009 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v9 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0010 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v10 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0011 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v11 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0012 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v12 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0013 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v13 database-test
  compose --profile data run --rm -e MIGRATION_TARGET=0014 migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-v14 database-test
  compose --profile data run --rm migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-latest database-test
  compose --profile data run --rm migrate
  cleanup_project "$COMPOSE_PROJECT_NAME"
}

run_clean_scenario
run_upgrade_scenario

echo 'Database migrations passed from a clean database and through the compatible N to N+1 path.'

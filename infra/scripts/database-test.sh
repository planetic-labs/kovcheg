#!/bin/sh

set -eu

mkdir -p "$PWD/.local"
test_root=$(mktemp -d "$PWD/.local/database-test.XXXXXX")
secret_root="$test_root/secrets"
base_project="kovcheg-db-$$"

mkdir -p "$secret_root"
export KOVCHEG_LOCAL_SECRET_DIR="$secret_root"
export COMPOSE_PARALLEL_LIMIT=1

compose() {
  sh infra/scripts/compose.sh "$@"
}

cleanup_project() {
  COMPOSE_PROJECT_NAME=$1 compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}

cleanup() {
  cleanup_status=$?
  if [ "$cleanup_status" -ne 0 ]; then
    for failed_project in "${base_project}-clean" "${base_project}-upgrade"; do
      COMPOSE_PROJECT_NAME="$failed_project" compose ps --all || true
      COMPOSE_PROJECT_NAME="$failed_project" compose logs --no-color postgres || true
    done
  fi
  cleanup_project "${base_project}-clean"
  cleanup_project "${base_project}-upgrade"
  find "$test_root" -type f -delete
  find "$test_root" -depth -type d -empty -delete
}

trap cleanup EXIT INT TERM

run_clean_scenario() {
  export COMPOSE_PROJECT_NAME="${base_project}-clean"
  compose up --detach --wait postgres
  compose --profile data run --rm migrate
  compose --profile data run --rm -e TEST_SCENARIO=clean database-test
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
  compose --profile data run --rm migrate
  compose --profile data run --rm -e TEST_SCENARIO=upgrade-latest database-test
  compose --profile data run --rm migrate
  cleanup_project "$COMPOSE_PROJECT_NAME"
}

run_clean_scenario
run_upgrade_scenario

echo 'Database migrations passed from a clean database and through the compatible N to N+1 path.'

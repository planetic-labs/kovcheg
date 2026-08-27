#!/bin/sh

set -eu

. infra/scripts/docker-test-lifecycle.sh

realtime_project="kovcheg-realtime-$$"
docker_test_begin realtime-smoke "$realtime_project"
docker_test_configure_compose_images "kovcheg-test-realtime-$KOVCHEG_TEST_RUN_ID"
docker_storage_preflight
mkdir -p "$PWD/.local"
realtime_secret_directory=$(mktemp -d "$PWD/.local/realtime-smoke.XXXXXX")
export KOVCHEG_LOCAL_SECRET_DIR="$realtime_secret_directory"

compose() {
  sh infra/scripts/compose.sh \
    -f compose.yaml \
    -f infra/realtime/compose.test.yaml \
    -f infra/testing/compose.lifecycle.yaml \
    -p "$realtime_project" \
    "$@"
}

cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  lifecycle_status=0
  if [ "$exit_code" -ne 0 ]; then
    compose ps
    compose logs --no-color --tail 100 api-1 api-2 auth worker redis edge
  fi
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker_test_finish || lifecycle_status=$?
  find "$realtime_secret_directory" -type f -delete
  find "$realtime_secret_directory" -depth -type d -empty -delete
  docker_test_remove_state
  if [ "$exit_code" -ne 0 ]; then
    return "$exit_code"
  fi
  if [ "$lifecycle_status" -ne 0 ]; then
    return "$lifecycle_status"
  fi
  return "$exit_code"
}

trap cleanup EXIT INT TERM

export BUILD_COMMIT_SHA=''
export BUILD_IMAGE_DIGEST=''
export COMPOSE_PARALLEL_LIMIT=1

compose config --quiet
compose up --detach --wait postgres redis
compose --profile data run --rm migrate
compose --profile data run --rm \
  --entrypoint sh migrate /workspace/infra/postgres/configure-local-auth.sh
compose --profile data run --rm -e TEST_SCENARIO=persona-message-fixture database-test
compose --profile data run --rm message-flow-test
compose up --build --detach --wait

REALTIME_COMPOSE_PROJECT="$realtime_project" \
  node infra/scripts/realtime-smoke.mjs http://127.0.0.1:3000 polling
REALTIME_COMPOSE_PROJECT="$realtime_project" \
  node infra/scripts/realtime-smoke.mjs http://127.0.0.1:3000 websocket

echo 'Realtime smoke passed polling and websocket cross-instance delivery, stickiness, reconnect catch-up, Redis recovery, and one-API failover.'

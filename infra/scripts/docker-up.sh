#!/bin/sh

set -eu

. infra/scripts/docker-test-lifecycle.sh

export KOVCHEG_TEST_PROJECT='kovcheg'
export KOVCHEG_TEST_PURPOSE='local-development'
export KOVCHEG_TEST_RUN_ID="local-development-$$"
export KOVCHEG_TEST_SOURCE_SHA="$(git rev-parse HEAD)"
docker_storage_preflight

compose() {
  sh infra/scripts/compose.sh "$@"
}

compose up --detach --wait postgres redis
compose --profile data run --rm migrate
compose --profile data run --rm \
  --entrypoint sh migrate /workspace/infra/postgres/configure-local-auth.sh
compose up --build --detach --wait

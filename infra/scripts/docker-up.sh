#!/bin/sh

set -eu

compose() {
  sh infra/scripts/compose.sh "$@"
}

compose up --detach --wait postgres redis
compose --profile data run --rm migrate
compose --profile data run --rm \
  --entrypoint sh migrate /workspace/infra/postgres/configure-local-auth.sh
compose up --build --detach --wait

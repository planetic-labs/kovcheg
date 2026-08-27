#!/bin/sh

set -eu

. infra/scripts/docker-test-lifecycle.sh

smoke_project="kovcheg-smoke-$$"
docker_test_begin docker-smoke "$smoke_project"
docker_test_configure_compose_images "kovcheg-test-docker-smoke-$KOVCHEG_TEST_RUN_ID"
docker_storage_preflight
mkdir -p "$PWD/.local"
smoke_secret_directory=$(mktemp -d "$PWD/.local/docker-smoke.XXXXXX")
export KOVCHEG_LOCAL_SECRET_DIR="$smoke_secret_directory"

compose() {
  sh infra/scripts/compose.sh \
    --file compose.yaml \
    --file infra/testing/compose.lifecycle.yaml \
    -p "$smoke_project" \
    "$@"
}

cleanup() {
  cleanup_status=$?
  lifecycle_status=0
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker_test_finish || lifecycle_status=$?
  find "$smoke_secret_directory" -type f -delete
  find "$smoke_secret_directory" -depth -type d -empty -delete
  docker_test_remove_state
  if [ "$cleanup_status" -ne 0 ]; then
    return "$cleanup_status"
  fi
  return "$lifecycle_status"
}

trap cleanup EXIT INT TERM

export BUILD_COMMIT_SHA
if [ -z "$(git status --porcelain --untracked-files=normal)" ]; then
  BUILD_COMMIT_SHA=$(git rev-parse HEAD)
else
  BUILD_COMMIT_SHA=''
fi
export BUILD_IMAGE_DIGEST=''
export COMPOSE_PARALLEL_LIMIT=1

compose config --quiet

expected_services=$(printf '%s\n' api-1 api-2 auth edge postgres redis web worker)
actual_services=$(compose config --services | sort)
if [ "$actual_services" != "$expected_services" ]; then
  echo 'Compose must contain exactly the eight documented local services.' >&2
  exit 1
fi

compose up --detach --wait postgres redis
compose --profile data run --rm migrate
compose --profile data run --rm \
  --entrypoint sh migrate /workspace/infra/postgres/configure-local-auth.sh
compose up --build --detach --wait

actual_bindings=$(
  for service in $actual_services; do
    container_id=$(compose ps --quiet "$service")
    bindings=$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$container_id")
    SERVICE="$service" BINDINGS="$bindings" node --input-type=module -e "
const bindings = JSON.parse(process.env.BINDINGS ?? 'null') ?? {};
for (const [containerPort, published] of Object.entries(bindings)) {
  for (const binding of published ?? []) {
    console.log(process.env.SERVICE + ' ' + containerPort + ' ' + binding.HostIp + ':' + binding.HostPort);
  }
}
"
  done | sort
)

expected_bindings='edge 8080/tcp 127.0.0.1:3000'
if [ "$actual_bindings" != "$expected_bindings" ]; then
  echo 'Published ports must equal the single edge loopback binding.' >&2
  exit 1
fi

if [ "$(docker network inspect --format '{{.Internal}}' "${smoke_project}_local")" != 'true' ]; then
  echo 'The local Compose network must remain internal.' >&2
  exit 1
fi
if [ "$(docker network inspect --format '{{.Internal}}' "${smoke_project}_host-loopback")" != 'false' ]; then
  echo 'The edge host-loopback bridge must remain a separate local Docker network.' >&2
  exit 1
fi

for service in $actual_services; do
  container_id=$(compose ps --quiet "$service")
  networks=$(docker inspect --format '{{json .NetworkSettings.Networks}}' "$container_id")
  SERVICE="$service" NETWORKS="$networks" SMOKE_PROJECT="$smoke_project" node --input-type=module -e "
import assert from 'node:assert/strict';
const actual = Object.keys(JSON.parse(process.env.NETWORKS ?? '{}')).sort();
const expected = process.env.SERVICE === 'edge'
  ? [process.env.SMOKE_PROJECT + '_host-loopback', process.env.SMOKE_PROJECT + '_local']
  : [process.env.SMOKE_PROJECT + '_local'];
assert.deepEqual(actual, expected, process.env.SERVICE + ' is attached to an unexpected Docker network set');
"
done

node infra/scripts/docker-smoke.mjs http://127.0.0.1:3000

smoke_session_token=$(compose exec -T auth node --input-type=module <infra/scripts/create-smoke-session.mjs)
deactivated_session_token=$(
  compose exec -T \
    -e KOVCHEG_SMOKE_ADMIN_SESSION_TOKEN="$smoke_session_token" \
    auth node --input-type=module <infra/scripts/create-deactivated-smoke-session.mjs
)
KOVCHEG_SMOKE_SESSION_TOKEN="$smoke_session_token" \
KOVCHEG_SMOKE_DEACTIVATED_SESSION_TOKEN="$deactivated_session_token" \
  node infra/scripts/session-contract-smoke.mjs http://127.0.0.1:3000
unset smoke_session_token deactivated_session_token

compose exec -T worker node --input-type=module -e "
import { readFile } from 'node:fs/promises';

const token = (await readFile('/run/secrets/realtime_relay_token', 'utf8')).trim();
const event = {
  contractVersion: 2,
  correlationId: 'relay-boundary-smoke-001',
  eventId: '00000000-0000-4000-8000-000000009901',
  eventName: 'message.created',
  occurredAt: '2026-01-01T00:00:00.000Z',
  payload: {
    chatId: '00000000-0000-4000-8000-000000009902',
    chatSequence: '1',
    messageId: '00000000-0000-4000-8000-000000009903',
    senderAccountId: '00000000-0000-4000-8000-000000009904',
  },
};
const request = (authorization) => ({
  body: JSON.stringify(event),
  headers: {
    ...(authorization === undefined ? {} : { authorization }),
    'content-type': 'application/json',
  },
  method: 'POST',
});

const publicResponse = await fetch(
  'http://edge:8080/api/internal/realtime/events',
  request('Bearer ' + token),
);
if (publicResponse.status !== 404) {
  throw new Error('The internal realtime relay route is reachable through the public entrypoint');
}

const unauthorizedResponse = await fetch(
  'http://edge:8081/internal/realtime/events',
  request(),
);
if (unauthorizedResponse.status !== 401) {
  throw new Error('The internal realtime relay route accepted a request without its bearer token');
}

const internalResponse = await fetch(
  'http://edge:8081/internal/realtime/events',
  request('Bearer ' + token),
);
if (internalResponse.status !== 202) {
  throw new Error('The internal realtime relay route rejected its worker credential');
}
"

compose exec -T worker node --input-type=module -e "
const response = await fetch('http://127.0.0.1:3003/health/ready', {
  headers: { 'x-correlation-id': 'worker-smoke-001' },
});
if (!response.ok) throw new Error('worker readiness failed');
if (response.headers.get('x-correlation-id') !== 'worker-smoke-001') {
  throw new Error('worker correlation ID was not preserved');
}
const health = await response.json();
if (health.service !== 'worker' || health.status !== 'ok') {
  throw new Error('worker readiness contract is invalid');
}
"

for service in api-1 api-2 auth worker web; do
  container_id=$(compose ps --quiet "$service")
  image_id=$(docker inspect --format '{{.Image}}' "$container_id")
  revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image_id")
  if [ "$revision" != "$BUILD_COMMIT_SHA" ]; then
    echo "$service image revision label does not match the tested commit." >&2
    exit 1
  fi

  compose exec -T "$service" sh -c "
set -e
if find /app -type f \( -name '*.map' -o -name '*.ts' -o -name '*.spec.js' -o -name '*.test.js' -o -name '*.integration-check.js' \) | grep -q .; then
  echo 'runtime image contains source, test, integration-check, or sourcemap files' >&2
  exit 1
fi
for package_manager in corepack npm npx pnpm pnpx yarn yarnpkg; do
  if command -v \"\$package_manager\" >/dev/null 2>&1; then
    echo \"runtime image contains package manager: \$package_manager\" >&2
    exit 1
  fi
done
test ! -e /app/node_modules/typescript
test ! -e /app/node_modules/eslint
test ! -e /app/node_modules/vitest
test ! -e /usr/local/lib/node_modules/npm
test ! -e /usr/local/lib/node_modules/corepack
test ! -e /usr/local/bin/npm
test ! -e /usr/local/bin/npx
test ! -e /usr/local/bin/corepack
test ! -e /usr/local/bin/pnpm
test ! -e /usr/local/bin/pnpx
test ! -e /usr/local/bin/yarn
test ! -e /usr/local/bin/yarnpkg
if find /app -path '*/@kovcheg/contracts/dist/testing' -type d | grep -q .; then
  echo 'runtime image contains synthetic identity fixtures' >&2
  exit 1
fi
if [ -d /app/dist ] && grep -R -E -q 'identity-stub|KOVCHEG_IDENTITY_STUB_ENABLED|test-api-main' /app/dist; then
  echo 'runtime image contains an isolated identity-stub entrypoint' >&2
  exit 1
fi
test ! -e /app/test-api-main.mjs
test ! -d /app/apps/api
test ! -d /app/apps/auth
test ! -d /app/apps/worker
test ! -d /app/packages
"
done

for service in api-1 api-2 auth worker; do
  compose exec -T "$service" sh -c '
test ! -d /app/src
'
done

echo 'Local Docker smoke passed for eight containers, two API instances, same-origin Traefik routing, contracts, provenance, runtime contents, and local-only isolation.'

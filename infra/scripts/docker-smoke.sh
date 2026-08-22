#!/bin/sh

set -eu

smoke_project="kovcheg-smoke-$$"

compose() {
  sh infra/scripts/compose.sh -p "$smoke_project" "$@"
}

cleanup() {
  compose down --volumes --remove-orphans
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

expected_services=$(printf '%s\n' api auth edge postgres redis web worker)
actual_services=$(compose config --services | sort)
if [ "$actual_services" != "$expected_services" ]; then
  echo 'Compose must contain exactly the seven documented local services.' >&2
  exit 1
fi

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

for service in api auth worker web; do
  container_id=$(compose ps --quiet "$service")
  image_id=$(docker inspect --format '{{.Image}}' "$container_id")
  revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image_id")
  if [ "$revision" != "$BUILD_COMMIT_SHA" ]; then
    echo "$service image revision label does not match the tested commit." >&2
    exit 1
  fi

  compose exec -T "$service" sh -c "
if find /app -type f \( -name '*.map' -o -name '*.ts' -o -name '*.spec.js' -o -name '*.test.js' \) | grep -q .; then
  echo 'runtime image contains source, test, or sourcemap files' >&2
  exit 1
fi
test ! -e /app/node_modules/typescript
test ! -e /app/node_modules/eslint
test ! -e /app/node_modules/vitest
if find /app -path '*/@kovcheg/contracts/dist/testing' -type d | grep -q .; then
  echo 'runtime image contains synthetic identity fixtures' >&2
  exit 1
fi
test ! -d /app/apps/api
test ! -d /app/apps/auth
test ! -d /app/apps/worker
test ! -d /app/packages
"
done

for service in api auth worker; do
  compose exec -T "$service" sh -c '
test ! -d /app/src
'
done

echo 'Local Docker smoke passed for seven containers, same-origin routing, contracts, provenance, runtime contents, and local-only isolation.'

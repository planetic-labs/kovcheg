#!/bin/sh

set -eu

cleanup() {
  docker compose down --volumes --remove-orphans
}

trap cleanup EXIT INT TERM

docker compose config --quiet
COMPOSE_PARALLEL_LIMIT=1 docker compose up --build --detach --wait

assert_loopback_binding() {
  service=$1
  container_port=$2
  host_port=$3

  container_id=$(docker compose ps --quiet "$service")
  published_ip=$(docker inspect --format "{{(index (index .HostConfig.PortBindings \"$container_port/tcp\") 0).HostIp}}" "$container_id")
  published_port=$(docker inspect --format "{{(index (index .HostConfig.PortBindings \"$container_port/tcp\") 0).HostPort}}" "$container_id")

  if [ "$published_ip:$published_port" != "127.0.0.1:$host_port" ]; then
    echo "$service must publish only on 127.0.0.1:$host_port; got $published_ip:$published_port" >&2
    exit 1
  fi
}

assert_loopback_binding web 3000 3000
assert_loopback_binding api 3001 3001
assert_loopback_binding auth 3002 3002

docker compose exec -T web node --input-type=module -e "
const response = await fetch('http://127.0.0.1:3000/health/ready');
if (!response.ok) throw new Error('web readiness failed');
"

docker compose exec -T worker node --input-type=module -e "
const response = await fetch('http://127.0.0.1:3003/health/ready');
if (!response.ok) throw new Error('worker readiness failed');
"

for service in api auth; do
  docker compose exec -T "$service" node --input-type=module -e "
const health = await fetch('http://127.0.0.1:' + process.env.PORT + '/health/ready');
if (!health.ok) throw new Error('$service readiness failed');

const response = await fetch('http://127.0.0.1:' + process.env.PORT + '/openapi.json');
if (!response.ok) throw new Error('$service OpenAPI failed');

const document = await response.json();
if (typeof document.openapi !== 'string' || !document.paths?.['/health/ready']) {
  throw new Error('$service OpenAPI document is missing the readiness contract');
}
"
done

echo 'Local Docker smoke passed for six containers, health/readiness, OpenAPI, and loopback-only ports.'

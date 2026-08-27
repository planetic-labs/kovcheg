#!/bin/sh

set -eu

. infra/scripts/docker-test-lifecycle.sh

mkdir -p "$PWD/.local"
regression_root=$(mktemp -d "$PWD/.local/docker-lifecycle-regression.XXXXXX")
foreign_suffix="$$-$(basename "$regression_root")"
foreign_image="kovcheg-lifecycle-foreign:$foreign_suffix"
foreign_network="kovcheg-lifecycle-foreign-network-$foreign_suffix"
foreign_volume="kovcheg-lifecycle-foreign-volume-$foreign_suffix"
foreign_container="kovcheg-lifecycle-foreign-container-$foreign_suffix"
base_image='redis:8.2.1-bookworm@sha256:5fa2edb1e408fa8235e6db8fab01d1afaaae96c9403ba67b70feceb8661e8621'

cleanup_foreign() {
  docker rm --force --volumes "$foreign_container" >/dev/null 2>&1 || true
  docker network rm "$foreign_network" >/dev/null 2>&1 || true
  docker volume rm "$foreign_volume" >/dev/null 2>&1 || true
  docker image rm "$foreign_image" >/dev/null 2>&1 || true
  find "$regression_root" -type f -delete 2>/dev/null || true
  find "$regression_root" -depth -type d -empty -delete 2>/dev/null || true
}
trap cleanup_foreign EXIT INT TERM

volume_count_before=$(docker volume ls --quiet | sort -u | wc -l | tr -d ' ')

docker pull "$base_image" >/dev/null
if (KOVCHEG_DOCKER_MIN_FREE_GIB=invalid; docker_storage_preflight) >/dev/null 2>&1; then
  echo 'Docker storage preflight accepted an invalid threshold.' >&2
  exit 1
fi
if (KOVCHEG_DOCKER_MIN_FREE_GIB=999999; docker_storage_preflight) >/dev/null 2>&1; then
  echo 'Docker storage preflight did not fail closed below its required threshold.' >&2
  exit 1
fi
docker image tag "$base_image" "$foreign_image"
docker network create --label io.kovcheg.test.project=foreign "$foreign_network" >/dev/null
docker volume create --label io.kovcheg.test.project=foreign "$foreign_volume" >/dev/null
docker create --name "$foreign_container" --network "$foreign_network" \
  --label io.kovcheg.test.project=foreign "$base_image" redis-server --version >/dev/null

printf 'lifecycle regression\n' >"$regression_root/marker"
printf '%s\n' 'FROM scratch' 'COPY marker /marker' >"$regression_root/Dockerfile"

dangling_before=$(docker image ls --quiet --filter dangling=true | sort -u | wc -l | tr -d ' ')

run_owned_build() {
  expected_failure=$1
  (
    docker_test_begin lifecycle-regression "kovcheg-lifecycle-regression-$$"
    owned_image="kovcheg-lifecycle-regression:$KOVCHEG_TEST_RUN_ID"
    docker_test_register_image "$owned_image"
    cleanup() {
      status=$?
      trap - EXIT INT TERM
      docker_test_finish
      docker_test_remove_state
      return "$status"
    }
    trap cleanup EXIT INT TERM

    docker_storage_preflight
    docker_buildx_preflight
    docker build --platform linux/amd64 \
      --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
      --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
      --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
      --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
      --tag "$owned_image" "$regression_root" >/dev/null
    docker network create \
      --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
      --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
      --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
      --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
      "kovcheg-lifecycle-owned-network-$KOVCHEG_TEST_RUN_ID" >/dev/null
    docker volume create \
      --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
      --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
      --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
      --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
      "kovcheg-lifecycle-owned-volume-$KOVCHEG_TEST_RUN_ID" >/dev/null
    if [ "$expected_failure" = '1' ]; then
      false
    fi
  )
}

if run_owned_build 1; then
  echo 'Intentional failure regression unexpectedly succeeded.' >&2
  exit 1
fi
run_owned_build 0

docker image inspect "$foreign_image" >/dev/null
docker inspect "$foreign_container" >/dev/null
docker network inspect "$foreign_network" >/dev/null
docker volume inspect "$foreign_volume" >/dev/null

cleanup_foreign
trap - EXIT INT TERM

volume_count_after=$(docker volume ls --quiet | sort -u | wc -l | tr -d ' ')
if [ "$volume_count_after" != "$volume_count_before" ]; then
  echo "Docker lifecycle regression changed volume count: before=$volume_count_before after=$volume_count_after" >&2
  exit 1
fi

dangling_after=$(docker image ls --quiet --filter dangling=true | sort -u | wc -l | tr -d ' ')
if [ "$dangling_after" != "$dangling_before" ]; then
  echo "Docker lifecycle regression changed dangling images: before=$dangling_before after=$dangling_after" >&2
  exit 1
fi

echo 'Docker lifecycle regression passed failure cleanup, foreign-resource preservation, and stable dangling-image count.'

#!/bin/sh

# Shared ownership and cleanup primitives for disposable Docker verification runs.
# This file is sourced by test entrypoints and does not install traps by itself.

KOVCHEG_DOCKER_TEST_LABEL_PROJECT='io.kovcheg.test.project'
KOVCHEG_DOCKER_TEST_LABEL_PURPOSE='io.kovcheg.test.purpose'
KOVCHEG_DOCKER_TEST_LABEL_RUN='io.kovcheg.test.run-id'
KOVCHEG_DOCKER_TEST_LABEL_SOURCE='io.kovcheg.test.source-sha'

docker_test_validate_positive_integer() {
  value=$1
  name=$2
  case "$value" in
    '' | *[!0-9]* | 0)
      echo "$name must be a positive integer." >&2
      return 1
      ;;
  esac
}

docker_test_begin() {
  purpose=$1
  project_name=$2
  case "$purpose:$project_name" in
    *[!a-zA-Z0-9_.:-]* | *: | :*)
      echo 'Docker test purpose and project name contain unsupported characters.' >&2
      return 1
      ;;
  esac

  keep_images=${KOVCHEG_KEEP_TEST_IMAGES:-0}
  case "$keep_images" in
    0 | 1) ;;
    *) echo 'KOVCHEG_KEEP_TEST_IMAGES must equal 0 or 1.' >&2; return 1 ;;
  esac

  source_sha=$(git rev-parse HEAD)
  case "$source_sha" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *) echo 'Docker test ownership requires a Git source SHA.' >&2; return 1 ;;
  esac
  if [ "${#source_sha}" -ne 40 ]; then
    echo 'Docker test ownership requires a full Git source SHA.' >&2
    return 1
  fi

  mkdir -p "$PWD/.local"
  state_directory=$(mktemp -d "$PWD/.local/docker-test-lifecycle.XXXXXX")
  run_token=$(basename "$state_directory" | sed 's/^docker-test-lifecycle\.//' | tr '[:upper:]' '[:lower:]')

  export KOVCHEG_TEST_PROJECT='kovcheg'
  export KOVCHEG_TEST_PURPOSE="$purpose"
  export KOVCHEG_TEST_RUN_ID="$(date -u +%Y%m%dt%H%M%Sz)-$$-$run_token"
  export KOVCHEG_TEST_SOURCE_SHA="$source_sha"
  export KOVCHEG_TEST_COMPOSE_PROJECT="$project_name"
  export KOVCHEG_TEST_STATE_DIRECTORY="$state_directory"
  export KOVCHEG_TEST_IMAGE_TAGS_FILE="$state_directory/image-tags"
  export KOVCHEG_TEST_IMAGE_RECORDS_FILE="$state_directory/image-records.tsv"
  export KOVCHEG_KEEP_TEST_IMAGES="$keep_images"

  : >"$KOVCHEG_TEST_IMAGE_TAGS_FILE"
  : >"$KOVCHEG_TEST_IMAGE_RECORDS_FILE"
}

docker_test_label_arguments() {
  printf '%s\n' \
    --label "$KOVCHEG_DOCKER_TEST_LABEL_PROJECT=$KOVCHEG_TEST_PROJECT" \
    --label "$KOVCHEG_DOCKER_TEST_LABEL_PURPOSE=$KOVCHEG_TEST_PURPOSE" \
    --label "$KOVCHEG_DOCKER_TEST_LABEL_RUN=$KOVCHEG_TEST_RUN_ID" \
    --label "$KOVCHEG_DOCKER_TEST_LABEL_SOURCE=$KOVCHEG_TEST_SOURCE_SHA"
}

docker_storage_preflight() {
  required_gib=${KOVCHEG_DOCKER_MIN_FREE_GIB:-20}
  docker_test_validate_positive_integer "$required_gib" KOVCHEG_DOCKER_MIN_FREE_GIB || return 1

  probe_image='redis:8.2.1-bookworm@sha256:5fa2edb1e408fa8235e6db8fab01d1afaaae96c9403ba67b70feceb8661e8621'
  available_kib=$(
    docker run --rm --pull=missing --network none --read-only \
      --label "$KOVCHEG_DOCKER_TEST_LABEL_PROJECT=${KOVCHEG_TEST_PROJECT:-kovcheg}" \
      --label "$KOVCHEG_DOCKER_TEST_LABEL_PURPOSE=${KOVCHEG_TEST_PURPOSE:-storage-preflight}" \
      --label "$KOVCHEG_DOCKER_TEST_LABEL_RUN=${KOVCHEG_TEST_RUN_ID:-preflight-$$}" \
      --label "$KOVCHEG_DOCKER_TEST_LABEL_SOURCE=${KOVCHEG_TEST_SOURCE_SHA:-$(git rev-parse HEAD)}" \
      --entrypoint sh "$probe_image" \
      -c 'df -Pk / | awk "NR == 2 { print \$4 }"'
  )
  case "$available_kib" in
    '' | *[!0-9]*)
      echo 'Unable to measure Docker-daemon free storage.' >&2
      return 1
      ;;
  esac

  available_gib=$((available_kib / 1024 / 1024))
  if [ "$available_gib" -lt "$required_gib" ]; then
    echo "Docker storage preflight failed: available=${available_gib}GiB required=${required_gib}GiB." >&2
    echo 'Review project-owned stale resources with: pnpm docker:resources' >&2
    echo 'No automatic cleanup was attempted.' >&2
    return 1
  fi
  echo "Docker storage preflight passed: available=${available_gib}GiB required=${required_gib}GiB."
}

docker_test_register_image() {
  image=$1
  case "$image" in
    '' | *[!a-zA-Z0-9_./:-]*)
      echo "Unsafe temporary image reference: $image" >&2
      return 1
      ;;
  esac
  if ! grep -F -x -q "$image" "$KOVCHEG_TEST_IMAGE_TAGS_FILE"; then
    printf '%s\n' "$image" >>"$KOVCHEG_TEST_IMAGE_TAGS_FILE"
  fi
}

docker_test_configure_compose_images() {
  prefix=$1
  export KOVCHEG_TEST_API_IMAGE="$prefix-api"
  export KOVCHEG_TEST_AUTH_IMAGE="$prefix-auth"
  export KOVCHEG_TEST_WEB_IMAGE="$prefix-web"
  export KOVCHEG_TEST_WORKER_IMAGE="$prefix-worker"
  export KOVCHEG_TEST_MESSAGE_FLOW_IMAGE="$prefix-message-flow"
  export KOVCHEG_TEST_AUTH_INTEGRATION_IMAGE="$prefix-auth-integration"
  docker_test_register_image "$KOVCHEG_TEST_API_IMAGE"
  docker_test_register_image "$KOVCHEG_TEST_AUTH_IMAGE"
  docker_test_register_image "$KOVCHEG_TEST_WEB_IMAGE"
  docker_test_register_image "$KOVCHEG_TEST_WORKER_IMAGE"
  docker_test_register_image "$KOVCHEG_TEST_MESSAGE_FLOW_IMAGE"
  docker_test_register_image "$KOVCHEG_TEST_AUTH_INTEGRATION_IMAGE"
}

docker_test_assert_image_ownership() {
  image=$1
  actual_project=$(docker image inspect --format "{{index .Config.Labels \"$KOVCHEG_DOCKER_TEST_LABEL_PROJECT\"}}" "$image")
  actual_purpose=$(docker image inspect --format "{{index .Config.Labels \"$KOVCHEG_DOCKER_TEST_LABEL_PURPOSE\"}}" "$image")
  actual_run=$(docker image inspect --format "{{index .Config.Labels \"$KOVCHEG_DOCKER_TEST_LABEL_RUN\"}}" "$image")
  actual_source=$(docker image inspect --format "{{index .Config.Labels \"$KOVCHEG_DOCKER_TEST_LABEL_SOURCE\"}}" "$image")
  if [ "$actual_project" != "$KOVCHEG_TEST_PROJECT" ] || \
    [ "$actual_purpose" != "$KOVCHEG_TEST_PURPOSE" ] || \
    [ "$actual_run" != "$KOVCHEG_TEST_RUN_ID" ] || \
    [ "$actual_source" != "$KOVCHEG_TEST_SOURCE_SHA" ]; then
    echo "Refusing to remove image without exact current-run ownership: $image" >&2
    return 1
  fi
}

docker_test_capture_images() {
  [ -f "$KOVCHEG_TEST_IMAGE_TAGS_FILE" ] || return 0
  : >"$KOVCHEG_TEST_IMAGE_RECORDS_FILE"
  while IFS= read -r image; do
    [ -n "$image" ] || continue
    if docker image inspect "$image" >/dev/null 2>&1; then
      docker_test_assert_image_ownership "$image"
      image_id=$(docker image inspect --format '{{.Id}}' "$image")
      architecture=$(docker image inspect --format '{{.Architecture}}' "$image")
      repo_digests=$(docker image inspect --format '{{join .RepoDigests ","}}' "$image")
      oci_revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")
      source_label=$(docker image inspect --format "{{index .Config.Labels \"$KOVCHEG_DOCKER_TEST_LABEL_SOURCE\"}}" "$image")
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$image" "$image_id" "$architecture" "$repo_digests" "$oci_revision" "$source_label" \
        >>"$KOVCHEG_TEST_IMAGE_RECORDS_FILE"
    fi
  done <"$KOVCHEG_TEST_IMAGE_TAGS_FILE"
}

docker_test_remove_owned_resources() {
  project_filter="label=$KOVCHEG_DOCKER_TEST_LABEL_PROJECT=$KOVCHEG_TEST_PROJECT"
  purpose_filter="label=$KOVCHEG_DOCKER_TEST_LABEL_PURPOSE=$KOVCHEG_TEST_PURPOSE"
  run_filter="label=$KOVCHEG_DOCKER_TEST_LABEL_RUN=$KOVCHEG_TEST_RUN_ID"
  source_filter="label=$KOVCHEG_DOCKER_TEST_LABEL_SOURCE=$KOVCHEG_TEST_SOURCE_SHA"

  owned_containers=$(docker ps --all --quiet --filter "$project_filter" --filter "$purpose_filter" --filter "$run_filter" --filter "$source_filter")
  if [ -n "$owned_containers" ]; then
    docker rm --force $owned_containers >/dev/null
  fi
  owned_networks=$(docker network ls --quiet --filter "$project_filter" --filter "$purpose_filter" --filter "$run_filter" --filter "$source_filter")
  if [ -n "$owned_networks" ]; then
    docker network rm $owned_networks >/dev/null
  fi
  owned_volumes=$(docker volume ls --quiet --filter "$project_filter" --filter "$purpose_filter" --filter "$run_filter" --filter "$source_filter")
  if [ -n "$owned_volumes" ]; then
    docker volume rm $owned_volumes >/dev/null
  fi
}

docker_test_cleanup_images() {
  docker_test_capture_images
  if [ "$KOVCHEG_KEEP_TEST_IMAGES" = '1' ]; then
    echo "Keeping current-run test images by explicit KOVCHEG_KEEP_TEST_IMAGES=1: $KOVCHEG_TEST_IMAGE_RECORDS_FILE"
    return 0
  fi
  while IFS= read -r image; do
    [ -n "$image" ] || continue
    if docker image inspect "$image" >/dev/null 2>&1; then
      docker_test_assert_image_ownership "$image"
      docker image rm "$image" >/dev/null
    fi
  done <"$KOVCHEG_TEST_IMAGE_TAGS_FILE"
}

docker_test_assert_clean() {
  project_filter="label=$KOVCHEG_DOCKER_TEST_LABEL_PROJECT=$KOVCHEG_TEST_PROJECT"
  purpose_filter="label=$KOVCHEG_DOCKER_TEST_LABEL_PURPOSE=$KOVCHEG_TEST_PURPOSE"
  run_filter="label=$KOVCHEG_DOCKER_TEST_LABEL_RUN=$KOVCHEG_TEST_RUN_ID"
  source_filter="label=$KOVCHEG_DOCKER_TEST_LABEL_SOURCE=$KOVCHEG_TEST_SOURCE_SHA"

  if [ -n "$(docker ps --all --quiet --filter "$project_filter" --filter "$purpose_filter" --filter "$run_filter" --filter "$source_filter")" ] || \
    [ -n "$(docker network ls --quiet --filter "$project_filter" --filter "$purpose_filter" --filter "$run_filter" --filter "$source_filter")" ] || \
    [ -n "$(docker volume ls --quiet --filter "$project_filter" --filter "$purpose_filter" --filter "$run_filter" --filter "$source_filter")" ]; then
    echo 'Current Docker test run left owned containers, networks, or volumes.' >&2
    return 1
  fi
  if [ "$KOVCHEG_KEEP_TEST_IMAGES" != '1' ]; then
    while IFS= read -r image; do
      [ -n "$image" ] || continue
      if docker image inspect "$image" >/dev/null 2>&1; then
        echo "Current Docker test run left a temporary image: $image" >&2
        return 1
      fi
    done <"$KOVCHEG_TEST_IMAGE_TAGS_FILE"
  fi
}

docker_test_finish() {
  docker_test_remove_owned_resources
  docker_test_cleanup_images
  docker_test_assert_clean
}

docker_test_remove_state() {
  [ -n "${KOVCHEG_TEST_STATE_DIRECTORY:-}" ] || return 0
  find "$KOVCHEG_TEST_STATE_DIRECTORY" -type f -delete 2>/dev/null || true
  find "$KOVCHEG_TEST_STATE_DIRECTORY" -depth -type d -empty -delete 2>/dev/null || true
}

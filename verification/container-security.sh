#!/bin/sh

set -eu

. infra/scripts/docker-test-lifecycle.sh

if ! command -v docker >/dev/null 2>&1; then
  echo 'TOOL_UNAVAILABLE: docker' >&2
  node verification/trivy-summary.mjs --tool-unavailable docker
  exit 2
fi

sh verification/docker-lifecycle-smoke.sh

docker_test_begin container-security "kovcheg-container-security-$$"
docker_storage_preflight
docker_buildx_preflight
image_prefix="kovcheg-test-container-security-$KOVCHEG_TEST_RUN_ID"
export KOVCHEG_TEST_API_IMAGE="$image_prefix-api"
export KOVCHEG_TEST_AUTH_IMAGE="$image_prefix-auth"
export KOVCHEG_TEST_WEB_IMAGE="$image_prefix-web"
export KOVCHEG_TEST_WORKER_IMAGE="$image_prefix-worker"
export KOVCHEG_TEST_EDGE_IMAGE="$image_prefix-edge"
export KOVCHEG_TEST_POSTGRES_IMAGE="$image_prefix-postgres"
for image in \
  "$KOVCHEG_TEST_API_IMAGE" "$KOVCHEG_TEST_AUTH_IMAGE" \
  "$KOVCHEG_TEST_WEB_IMAGE" "$KOVCHEG_TEST_WORKER_IMAGE" \
  "$KOVCHEG_TEST_EDGE_IMAGE" "$KOVCHEG_TEST_POSTGRES_IMAGE"; do
  docker_test_register_image "$image"
done

cleanup() {
  cleanup_status=$?
  trap - EXIT INT TERM
  lifecycle_status=0
  docker_test_finish || lifecycle_status=$?
  mkdir -p .artifacts/security
  cp "$KOVCHEG_TEST_IMAGE_RECORDS_FILE" .artifacts/security/image-records.tsv 2>/dev/null || true
  docker_test_remove_state
  if [ "$cleanup_status" -ne 0 ]; then
    return "$cleanup_status"
  fi
  return "$lifecycle_status"
}
trap cleanup EXIT INT TERM

if ! command -v trivy >/dev/null 2>&1; then
  echo 'TOOL_UNAVAILABLE: trivy' >&2
  node verification/trivy-summary.mjs --tool-unavailable trivy
  exit 2
fi

artifact_directory='.artifacts/security'
mkdir -p "$artifact_directory"
scan_status=0
blocking_status=0
build_revision=${GITHUB_SHA:-local}

scan_image_artifacts() {
  application=$1
  image=$2
  image_archive="$KOVCHEG_TEST_STATE_DIRECTORY/$application-image.tar"

  if ! docker image save --output "$image_archive" "$image"; then
    scan_status=1
    return
  fi

  if ! trivy image \
    --input "$image_archive" \
    --scanners vuln \
    --format json \
    --exit-code 0 \
    --output "$artifact_directory/$application-image.json"; then
    scan_status=1
  fi

  if ! trivy image \
    --input "$image_archive" \
    --format cyclonedx \
    --output "$artifact_directory/$application-sbom.cdx.json"; then
    scan_status=1
  fi

  if ! trivy image \
    --input "$image_archive" \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --ignore-unfixed \
    --format json \
    --exit-code 1 \
    --output "$artifact_directory/$application-fixed-high-critical.json"; then
    blocking_status=1
  fi

  rm -f "$image_archive"
}

if ! trivy fs \
  --scanners vuln,misconfig \
  --skip-dirs .artifacts \
  --skip-dirs .git \
  --skip-dirs apps/web/.next \
  --skip-dirs node_modules \
  --format json \
  --exit-code 0 \
  --output "$artifact_directory/filesystem.json" \
  .; then
  scan_status=1
fi

for application in api auth web worker; do
  case "$application" in
    api) image=$KOVCHEG_TEST_API_IMAGE ;;
    auth) image=$KOVCHEG_TEST_AUTH_IMAGE ;;
    web) image=$KOVCHEG_TEST_WEB_IMAGE ;;
    worker) image=$KOVCHEG_TEST_WORKER_IMAGE ;;
  esac
  if ! docker build \
    --platform linux/amd64 \
    --file "apps/$application/Dockerfile" \
    --target runtime \
    --build-arg "BUILD_COMMIT_SHA=$build_revision" \
    --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
    --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
    --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
    --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
    --tag "$image" \
    .; then
    scan_status=1
    continue
  fi

  if [ "$(docker image inspect --format '{{.Architecture}}' "$image")" != 'amd64' ]; then
    scan_status=1
  fi

  scan_image_artifacts "$application" "$image"
done

for deployment_image in edge postgres; do
  case "$deployment_image" in
    edge)
      image=$KOVCHEG_TEST_EDGE_IMAGE
      dockerfile='infra/edge/Dockerfile'
      context='infra/edge'
      ;;
    postgres)
      image=$KOVCHEG_TEST_POSTGRES_IMAGE
      dockerfile='infra/postgres/Dockerfile'
      context='infra/postgres'
      ;;
  esac
  if ! docker build \
    --platform linux/amd64 \
    --file "$dockerfile" \
    --target runtime \
    --build-arg "BUILD_COMMIT_SHA=$build_revision" \
    --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
    --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
    --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
    --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
    --tag "$image" \
    "$context"; then
    scan_status=1
    continue
  fi
  if [ "$(docker image inspect --format '{{.Architecture}}' "$image")" != 'amd64' ]; then
    scan_status=1
  fi
  scan_image_artifacts "$deployment_image" "$image"
done

TRIVY_SCAN_STATUS=$scan_status TRIVY_BLOCKING_STATUS=$blocking_status \
  node verification/trivy-summary.mjs

if [ "$scan_status" -ne 0 ] || [ "$blocking_status" -ne 0 ]; then
  exit 1
fi

#!/bin/sh

set -eu

. infra/scripts/docker-test-lifecycle.sh

if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  echo 'Deployment smoke requires a clean exact commit.' >&2
  exit 1
fi

revision=$(git rev-parse HEAD)
case "$revision" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
  *) echo 'A full source revision is required.' >&2; exit 1 ;;
esac
if [ "${#revision}" -ne 40 ]; then
  echo 'A full source revision is required.' >&2
  exit 1
fi

project="kovcheg-deployment-smoke-$$"
docker_test_begin deployment-smoke "$project"
docker_storage_preflight
if ! docker buildx version >/dev/null 2>&1; then
  echo 'Deployment smoke requires the official Docker Buildx plugin for linux/amd64 images.' >&2
  exit 1
fi
image_prefix="kovcheg-test-deployment-$KOVCHEG_TEST_RUN_ID"
export KOVCHEG_LOCAL_SECRET_DIR="$PWD/.local/$project-secrets"
export KOVCHEG_LOOPBACK_PORT=$((32000 + ($$ % 1000)))
export KOVCHEG_API_IMAGE="$image_prefix-api"
export KOVCHEG_AUTH_IMAGE="$image_prefix-auth"
export KOVCHEG_WEB_IMAGE="$image_prefix-web"
export KOVCHEG_WORKER_IMAGE="$image_prefix-worker"
export KOVCHEG_EDGE_IMAGE="$image_prefix-edge"
export KOVCHEG_POSTGRES_IMAGE="$image_prefix-postgres"
docker_test_register_image "$KOVCHEG_API_IMAGE"
docker_test_register_image "$KOVCHEG_AUTH_IMAGE"
docker_test_register_image "$KOVCHEG_WEB_IMAGE"
docker_test_register_image "$KOVCHEG_WORKER_IMAGE"
docker_test_register_image "$KOVCHEG_EDGE_IMAGE"
docker_test_register_image "$KOVCHEG_POSTGRES_IMAGE"
synthetic_digest="sha256:$(printf 'a%.0s' $(seq 1 64))"
export KOVCHEG_API_IMAGE_DIGEST="$synthetic_digest"
export KOVCHEG_AUTH_IMAGE_DIGEST="$synthetic_digest"
export KOVCHEG_WEB_IMAGE_DIGEST="$synthetic_digest"
export KOVCHEG_WORKER_IMAGE_DIGEST="$synthetic_digest"
export KOVCHEG_AUTH_EMAIL_FROM_ADDRESS='sender@deployment.invalid'
export KOVCHEG_AUTH_EMAIL_FROM_NAME='Synthetic Deployment Sender'
export KOVCHEG_AUTH_OIDC_ISSUER='https://auth-deployment.invalid'
export KOVCHEG_AUTH_WEBAUTHN_ORIGINS_JSON='["https://auth-deployment.invalid"]'
export KOVCHEG_AUTH_WEBAUTHN_RP_ID='auth-deployment.invalid'
export KOVCHEG_AUTH_WEBAUTHN_RP_NAME='Synthetic Deployment'

compose() {
  sh infra/scripts/compose.sh \
    --file infra/deployment/compose.yaml \
    --file infra/deployment/compose.lifecycle.yaml \
    --project-name "$project" \
    "$@"
}

cleanup() {
  cleanup_status=$?
  lifecycle_status=0
  if [ "$cleanup_status" -ne 0 ]; then
    compose ps --all || true
    compose logs --no-color --tail=120 || true
  fi
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker_test_finish || lifecycle_status=$?
  mkdir -p .artifacts/deployment
  cp "$KOVCHEG_TEST_IMAGE_RECORDS_FILE" ".artifacts/deployment/images-$revision.tsv" 2>/dev/null || true
  find "$KOVCHEG_LOCAL_SECRET_DIR" -type f -delete 2>/dev/null || true
  find "$KOVCHEG_LOCAL_SECRET_DIR" -depth -type d -empty -delete 2>/dev/null || true
  docker_test_remove_state
  if [ "$cleanup_status" -ne 0 ]; then
    return "$cleanup_status"
  fi
  return "$lifecycle_status"
}
trap cleanup EXIT INT TERM

docker buildx build --load --platform linux/amd64 --target runtime --build-arg "BUILD_COMMIT_SHA=$revision" \
  --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
  --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
  --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
  --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
  --file apps/api/Dockerfile --tag "$KOVCHEG_API_IMAGE" .
docker buildx build --load --platform linux/amd64 --target runtime --build-arg "BUILD_COMMIT_SHA=$revision" \
  --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
  --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
  --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
  --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
  --file apps/auth/Dockerfile --tag "$KOVCHEG_AUTH_IMAGE" .
docker buildx build --load --platform linux/amd64 --target runtime --build-arg "BUILD_COMMIT_SHA=$revision" \
  --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
  --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
  --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
  --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
  --file apps/web/Dockerfile --tag "$KOVCHEG_WEB_IMAGE" .
docker buildx build --load --platform linux/amd64 --target runtime --build-arg "BUILD_COMMIT_SHA=$revision" \
  --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
  --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
  --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
  --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
  --file apps/worker/Dockerfile --tag "$KOVCHEG_WORKER_IMAGE" .
docker buildx build --load --platform linux/amd64 --target runtime --build-arg "BUILD_COMMIT_SHA=$revision" \
  --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
  --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
  --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
  --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
  --file infra/edge/Dockerfile --tag "$KOVCHEG_EDGE_IMAGE" infra/edge
docker buildx build --load --platform linux/amd64 --target runtime --build-arg "BUILD_COMMIT_SHA=$revision" \
  --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
  --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
  --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
  --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
  --file infra/postgres/Dockerfile --tag "$KOVCHEG_POSTGRES_IMAGE" infra/postgres

for image in \
  "$KOVCHEG_API_IMAGE" "$KOVCHEG_AUTH_IMAGE" "$KOVCHEG_WEB_IMAGE" \
  "$KOVCHEG_WORKER_IMAGE" "$KOVCHEG_EDGE_IMAGE" "$KOVCHEG_POSTGRES_IMAGE"; do
  architecture=$(docker image inspect --format '{{.Architecture}}' "$image")
  image_revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")
  if [ "$architecture" != 'amd64' ] || [ "$image_revision" != "$revision" ]; then
    echo "Image architecture or provenance mismatch: $image" >&2
    exit 1
  fi
done

compose config --quiet
compose up --detach --wait

base_url="http://127.0.0.1:$KOVCHEG_LOOPBACK_PORT"
BUILD_COMMIT_SHA="$revision" BUILD_IMAGE_DIGEST="$synthetic_digest" \
  node infra/scripts/docker-smoke.mjs "$base_url"

smoke_session_token=$(compose exec -T auth node --input-type=module <infra/scripts/create-smoke-session.mjs)
deactivated_session_token=$(
  compose exec -T -e KOVCHEG_SMOKE_ADMIN_SESSION_TOKEN="$smoke_session_token" \
    auth node --input-type=module <infra/scripts/create-deactivated-smoke-session.mjs
)
KOVCHEG_SMOKE_SESSION_TOKEN="$smoke_session_token" \
KOVCHEG_SMOKE_DEACTIVATED_SESSION_TOKEN="$deactivated_session_token" \
  node infra/scripts/session-contract-smoke.mjs "$base_url"
unset smoke_session_token deactivated_session_token

for service in postgres redis api-1 api-2 auth worker web edge; do
  container_id=$(compose ps --quiet "$service")
  limits=$(docker inspect --format '{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}' "$container_id")
  LIMITS="$limits" SERVICE="$service" node --input-type=module -e "
const values = (process.env.LIMITS ?? '').split(' ').map(Number);
if (values.length !== 3 || values.some((value) => !Number.isFinite(value) || value <= 0)) {
  throw new Error(process.env.SERVICE + ' resource limits were not applied');
}
"
done

cleanup
trap - EXIT INT TERM
echo 'Deployment candidate smoke passed with six amd64 images and no residual containers, networks, volumes, or temporary images.'

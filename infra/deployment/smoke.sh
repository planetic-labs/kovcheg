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
target_image_prefix="kovcheg-test-deployment-$KOVCHEG_TEST_RUN_ID-amd64"
export KOVCHEG_LOCAL_SECRET_DIR="$PWD/.local/$project-secrets"
export KOVCHEG_LOOPBACK_PORT=$((32000 + ($$ % 1000)))
target_api_image="$target_image_prefix-api"
target_auth_image="$target_image_prefix-auth"
target_web_image="$target_image_prefix-web"
target_worker_image="$target_image_prefix-worker"
target_edge_image="$target_image_prefix-edge"
target_postgres_image="$target_image_prefix-postgres"
for image in \
  "$target_api_image" "$target_auth_image" "$target_web_image" \
  "$target_worker_image" "$target_edge_image" "$target_postgres_image"; do
  docker_test_register_image "$image"
done
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
    --file infra/deployment/compose.smoke.yaml \
    --file infra/deployment/compose.lifecycle.yaml \
    --project-name "$project" \
    "$@"
}

cleanup() {
  cleanup_status=$?
  trap - EXIT INT TERM
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

build_image() {
  platform=$1
  dockerfile=$2
  image=$3
  context=$4
  docker buildx build --load --platform "$platform" --target runtime --build-arg "BUILD_COMMIT_SHA=$revision" \
  --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
  --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
  --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
  --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
    --file "$dockerfile" --tag "$image" "$context"
}

build_image_set() {
  build_image "$1" apps/api/Dockerfile "$2" .
  build_image "$1" apps/auth/Dockerfile "$3" .
  build_image "$1" apps/web/Dockerfile "$4" .
  build_image "$1" apps/worker/Dockerfile "$5" .
  build_image "$1" infra/edge/Dockerfile "$6" infra/edge
  build_image "$1" infra/postgres/Dockerfile "$7" infra/postgres
}

build_image_set linux/amd64 \
  "$target_api_image" "$target_auth_image" "$target_web_image" \
  "$target_worker_image" "$target_edge_image" "$target_postgres_image"

for image in \
  "$target_api_image" "$target_auth_image" "$target_web_image" \
  "$target_worker_image" "$target_edge_image" "$target_postgres_image"; do
  architecture=$(docker image inspect --format '{{.Architecture}}' "$image")
  image_revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")
  if [ "$architecture" != 'amd64' ] || [ "$image_revision" != "$revision" ]; then
    echo "Image architecture or provenance mismatch: $image" >&2
    exit 1
  fi
done

mkdir -p .artifacts/deployment
target_manifest=".artifacts/deployment/amd64-images-$revision.tsv"
: >"$target_manifest"
for image in \
  "$target_api_image" "$target_auth_image" "$target_web_image" \
  "$target_worker_image" "$target_edge_image" "$target_postgres_image"; do
  docker image inspect --format '{{.RepoTags}}\t{{.Id}}\t{{.Architecture}}\t{{index .Config.Labels "org.opencontainers.image.revision"}}\t{{index .Config.Labels "io.kovcheg.test.source-sha"}}' "$image" \
    >>"$target_manifest"
done

daemon_architecture=$(docker info --format '{{.Architecture}}')
case "$daemon_architecture" in
  amd64 | x86_64) runtime_platform=linux/amd64 ;;
  arm64 | aarch64) runtime_platform=linux/arm64 ;;
  *) echo "Unsupported Docker daemon architecture for deployment smoke: $daemon_architecture" >&2; exit 1 ;;
esac
export KOVCHEG_DEPLOYMENT_SMOKE_PLATFORM="$runtime_platform"

if [ "$runtime_platform" = 'linux/amd64' ]; then
  export KOVCHEG_API_IMAGE="$target_api_image"
  export KOVCHEG_AUTH_IMAGE="$target_auth_image"
  export KOVCHEG_WEB_IMAGE="$target_web_image"
  export KOVCHEG_WORKER_IMAGE="$target_worker_image"
  export KOVCHEG_EDGE_IMAGE="$target_edge_image"
  export KOVCHEG_POSTGRES_IMAGE="$target_postgres_image"
else
  runtime_image_prefix="kovcheg-test-deployment-$KOVCHEG_TEST_RUN_ID-runtime"
  export KOVCHEG_API_IMAGE="$runtime_image_prefix-api"
  export KOVCHEG_AUTH_IMAGE="$runtime_image_prefix-auth"
  export KOVCHEG_WEB_IMAGE="$runtime_image_prefix-web"
  export KOVCHEG_WORKER_IMAGE="$runtime_image_prefix-worker"
  export KOVCHEG_EDGE_IMAGE="$runtime_image_prefix-edge"
  export KOVCHEG_POSTGRES_IMAGE="$runtime_image_prefix-postgres"
  for image in \
    "$KOVCHEG_API_IMAGE" "$KOVCHEG_AUTH_IMAGE" "$KOVCHEG_WEB_IMAGE" \
    "$KOVCHEG_WORKER_IMAGE" "$KOVCHEG_EDGE_IMAGE" "$KOVCHEG_POSTGRES_IMAGE"; do
    docker_test_register_image "$image"
  done
  build_image_set "$runtime_platform" \
    "$KOVCHEG_API_IMAGE" "$KOVCHEG_AUTH_IMAGE" "$KOVCHEG_WEB_IMAGE" \
    "$KOVCHEG_WORKER_IMAGE" "$KOVCHEG_EDGE_IMAGE" "$KOVCHEG_POSTGRES_IMAGE"
fi

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
echo "Deployment candidate smoke passed: six linux/amd64 target images verified; runtime integration passed on $runtime_platform; no residual owned resources."

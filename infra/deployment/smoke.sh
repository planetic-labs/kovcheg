#!/bin/sh

set -eu

. infra/scripts/docker-test-lifecycle.sh

build_only=0
build_output=''
case "${1:-}" in
  '') [ "$#" -eq 0 ] || exit 1 ;;
  --build-only)
    [ "$#" -eq 2 ] || { echo 'Usage: smoke.sh --build-only ABSENT_OUTPUT_DIRECTORY' >&2; exit 1; }
    build_only=1
    build_output=$2
    ;;
  *) echo 'Unknown deployment smoke option.' >&2; exit 1 ;;
esac

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

source_tree=$(git rev-parse 'HEAD^{tree}')
if [ "$build_only" = '1' ]; then
  node --input-type=module - "$build_output" <<'JS'
import assert from 'node:assert/strict';
import {existsSync, lstatSync, mkdirSync, realpathSync} from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const output = process.argv[2];
const git = (...args) => execFileSync('git', args, {encoding:'utf8'}).trim();
const root = realpathSync('.');
assert.equal(git('rev-parse','--show-toplevel'), root);
assert.equal(git('remote','get-url','origin'), 'https://github.com/planetic-labs/kovcheg.git');
assert(path.isAbsolute(output) && path.normalize(output) === output);
assert.equal(realpathSync(path.dirname(output)), path.dirname(output));
assert(!existsSync(output));
assert.throws(() => lstatSync(output), {code:'ENOENT'});
assert(output !== root && !output.startsWith(root + path.sep));
assert(!git('ls-tree','-r','HEAD').split('\n').some(line => /^(120000|160000) /u.test(line)));
mkdirSync(output, {mode:0o700});
JS
fi

project="kovcheg-deployment-smoke-$$"
docker_test_begin deployment-smoke "$project"
if [ "$build_only" = '0' ]; then
  docker_storage_preflight
  docker_buildx_preflight
fi
target_image_prefix="kovcheg-test-deployment-$KOVCHEG_TEST_RUN_ID-amd64"
export KOVCHEG_LOCAL_SECRET_DIR="$PWD/.local/$project-secrets"
export KOVCHEG_LOOPBACK_PORT=$((32000 + ($$ % 1000)))
export KOVCHEG_AUTH_ISSUER_LOOPBACK_PORT=$((34000 + ($$ % 1000)))
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
export KOVCHEG_APP_ENV='staging'
export KOVCHEG_WEB_OIDC_AUTHORIZATION_ENDPOINT='https://auth-deployment.invalid/auth'
export KOVCHEG_WEB_OIDC_CLIENT_ID='synthetic-deployment-web'
export KOVCHEG_WEB_OIDC_ISSUER='https://auth-deployment.invalid'
export KOVCHEG_WEB_OIDC_REDIRECT_URI='https://app-deployment.invalid/bff/auth/oidc/callback'
export KOVCHEG_WEB_OIDC_TOKEN_ENDPOINT_AUTH_METHOD='none'

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
  if [ "$build_only" = '1' ]; then
    # Build-only has no runtime resources. Preserve ownership evidence on error;
    # retained images belong to the separately authorized local acceptance.
    metadata_status=0
    docker_test_capture_images || metadata_status=$?
    cp "$KOVCHEG_TEST_IMAGE_RECORDS_FILE" "$build_output/lifecycle-images.tsv"
    cp "$KOVCHEG_TEST_IMAGE_BASELINE_FILE" "$build_output/image-baseline"
    [ "$cleanup_status" -eq 0 ] || return "$cleanup_status"
    return "$metadata_status"
  fi
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

if [ "$build_only" = '1' ]; then
  docker_buildx_preflight
fi

# Local acceptance metadata only; never a publication or deployment receipt.
local_build_metadata() {
  node --input-type=module - "$@" <<'JS'
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {closeSync, createReadStream, lstatSync, openSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
const [operation, output, revision, sourceTree, dockerfile, context, image, state] = process.argv.slice(2);
const git = (...args) => execFileSync('git', args, {maxBuffer:32*1024*1024});
const text = (...args) => git(...args).toString().trim();
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fileHash = async file => {
  const digest = createHash('sha256');
  for await (const bytes of createReadStream(file)) digest.update(bytes);
  return digest.digest('hex');
};
const ids = ['api','auth','web','worker','edge','postgres'];
const exact = () => {
  assert.equal(text('rev-parse','HEAD'), revision);
  assert.equal(text('rev-parse','HEAD^{tree}'), sourceTree);
  assert.equal(text('status','--porcelain','--untracked-files=all'), '');
};
exact();
if (operation === 'finish') {
  const artifacts = ids.map(id => JSON.parse(readFileSync(output+'/'+id+'.json','utf8')));
  assert.deepEqual(artifacts.map(item=>item.artifact_id), ids);
  assert.equal(new Set(artifacts.map(item=>item.index_digest)).size, 6);
  writeFileSync(output+'/local-build-input.json', JSON.stringify({
    kind:'local-installed-update-builds-v1',old:null,
    new:{source_checkout:realpathSync('.'),source_commit:revision,source_tree:sourceTree,artifacts},
  },null,2)+'\n', {flag:'wx',mode:0o600});
} else {
  const id = dockerfile.split('/').at(-2);
  assert(ids.includes(id));
  const nested = id === 'edge' || id === 'postgres';
  assert.equal(context, nested ? 'infra/'+id : '.');
  assert.equal(dockerfile, (nested ? 'infra/' : 'apps/')+id+'/Dockerfile');
  const treeRef = context === '.' ? revision+'^{tree}' : revision+':'+context;
  assert(!text('ls-tree','-r',treeRef).split('\n').some(line => /^(120000|160000) /u.test(line)));
  const source = {
    artifact_id:id, context, dockerfile, context_tree:text('rev-parse',treeRef),
    context_archive_sha256:undefined, dockerfile_sha256:hash(git('show',revision+':'+dockerfile)),
  };
  const contextArchive = state+'/'+id+'-context.tar';
  if (operation === 'prepare') {
    const fd = openSync(contextArchive,'wx',0o600);
    try {
      const result = spawnSync('git',[
        'archive','--format=tar','--mtime=1970-01-01T00:00:00Z',
        context === '.' ? revision : revision+':'+context,
      ], {stdio:['ignore',fd,'pipe']});
      assert.equal(result.status,0,'Exact context archive failed');
    } finally { closeSync(fd); }
    source.context_archive_sha256 = await fileHash(contextArchive);
    writeFileSync(state+'/'+id+'-source.json',JSON.stringify(source),{flag:'wx',mode:0o600});
    console.log(source.context_archive_sha256+' '+source.dockerfile_sha256);
  } else {
    assert.equal(operation,'map');
    const recorded = JSON.parse(readFileSync(state+'/'+id+'-source.json','utf8'));
    assert.equal(await fileHash(contextArchive),recorded.context_archive_sha256);
    const archive = output+'/'+id+'.tar';
    assert(lstatSync(archive).isFile() && !lstatSync(archive).isSymbolicLink());
    const members = execFileSync('tar',['-tf',archive],{encoding:'utf8',maxBuffer:8*1024*1024}).trim().split('\n');
    const raw = name => {
      assert.equal(members.filter(member=>member === name).length,1,'Ambiguous OCI member');
      assert(execFileSync('tar',['-tvf',archive,name],{encoding:'utf8'}).startsWith('-'),'OCI identity must be a regular file');
      return execFileSync('tar',['-xOf',archive,name],{maxBuffer:8*1024*1024});
    };
    const blob = descriptor => {
      assert(/^sha256:[a-f0-9]{64}$/u.test(descriptor.digest));
      const bytes = raw('blobs/sha256/'+descriptor.digest.slice(7));
      assert.equal('sha256:'+hash(bytes),descriptor.digest);
      assert.equal(bytes.length,descriptor.size);
      return JSON.parse(bytes);
    };
    const layout = JSON.parse(raw('index.json'));
    assert.equal(layout.schemaVersion,2);
    assert.equal(layout.manifests?.length,1,'Exactly one exported image root is required');
    const rootDescriptor = layout.manifests[0];
    const root = blob(rootDescriptor);
    assert.equal(root.schemaVersion,2);
    let manifestDescriptor = rootDescriptor;
    if (root.manifests) {
      const matches = root.manifests.filter(item=>item.platform?.os==='linux' && item.platform?.architecture==='amd64');
      assert.equal(matches.length,1,'Exactly one linux/amd64 manifest is required');
      manifestDescriptor = matches[0];
    }
    const manifest = blob(manifestDescriptor);
    assert.equal(manifest.schemaVersion,2);
    const config = blob(manifest.config);
    assert.equal(config.os,'linux');
    assert.equal(config.architecture,'amd64');
    for (const [key,value] of Object.entries({
      'org.opencontainers.image.source':'https://github.com/planetic-labs/kovcheg',
      'org.opencontainers.image.revision':revision,
      'io.kovcheg.test.source-tree':sourceTree,
      'io.kovcheg.test.context-sha256':recorded.context_archive_sha256,
      'io.kovcheg.test.dockerfile-sha256':recorded.dockerfile_sha256,
    })) assert.equal(config.config?.Labels?.[key],value,'Image source label mismatch');
    const inspect = reference => JSON.parse(execFileSync('docker',['image','inspect',reference],{encoding:'utf8'}))[0];
    const byTag = inspect(image), byContent = inspect(rootDescriptor.digest);
    assert.equal(byTag.Id,byContent.Id,'Local root must address the built image');
    assert([rootDescriptor.digest,manifestDescriptor.digest,manifest.config.digest].includes(byContent.Id));
    writeFileSync(output+'/'+id+'.json',JSON.stringify({
      ...recorded,image_archive:realpathSync(archive),image_archive_sha256:await fileHash(archive),
      index_digest:rootDescriptor.digest,platform_manifest_digest:manifestDescriptor.digest,
      image_config_digest:manifest.config.digest,
    },null,2)+'\n',{flag:'wx',mode:0o600});
  }
}
JS
}

build_image() {
  platform=$1
  dockerfile=$2
  image=$3
  context=$4
  if [ "$build_only" = '1' ]; then
    id=$(basename "$(dirname "$dockerfile")")
    hashes=$(local_build_metadata prepare "$build_output" "$revision" "$source_tree" "$dockerfile" "$context" "$image" "$KOVCHEG_TEST_STATE_DIRECTORY")
    context_hash=${hashes% *}
    dockerfile_hash=${hashes#* }
    context_dockerfile=$dockerfile
    [ "$context" = '.' ] || context_dockerfile=Dockerfile
    existing_tag=$(docker image ls --format '{{.ID}}' --filter "reference=$image")
    if [ -n "$existing_tag" ]; then
      echo 'Local build tag collision; no overwrite is allowed.' >&2
      return 1
    fi
    docker buildx build --load --platform "$platform" --target runtime --build-arg "BUILD_COMMIT_SHA=$revision" \
      --label "io.kovcheg.test.project=$KOVCHEG_TEST_PROJECT" \
      --label "io.kovcheg.test.purpose=$KOVCHEG_TEST_PURPOSE" \
      --label "io.kovcheg.test.run-id=$KOVCHEG_TEST_RUN_ID" \
      --label "io.kovcheg.test.source-sha=$KOVCHEG_TEST_SOURCE_SHA" \
      --label 'org.opencontainers.image.source=https://github.com/planetic-labs/kovcheg' \
      --label "org.opencontainers.image.revision=$revision" \
      --label "io.kovcheg.test.source-tree=$source_tree" \
      --label "io.kovcheg.test.context-sha256=$context_hash" \
      --label "io.kovcheg.test.dockerfile-sha256=$dockerfile_hash" \
      --file "$context_dockerfile" --tag "$image" - <"$KOVCHEG_TEST_STATE_DIRECTORY/$id-context.tar"
    docker image save --output "$build_output/$id.tar" "$image"
    local_build_metadata map "$build_output" "$revision" "$source_tree" "$dockerfile" "$context" "$image" "$KOVCHEG_TEST_STATE_DIRECTORY"
    return
  fi
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

if [ "$build_only" = '1' ]; then
  # Ownership remains recorded for the separately authorized local consumer.
  cleanup
  trap - EXIT INT TERM
  local_build_metadata finish "$build_output" "$revision" "$source_tree"
  echo 'Local build-only input prepared: six retained amd64 images; no publication or runtime acceptance.'
  exit 0
fi

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
issuer_base_url="http://127.0.0.1:$KOVCHEG_AUTH_ISSUER_LOOPBACK_PORT"
KOVCHEG_SMOKE_SESSION_TOKEN="$smoke_session_token" \
  node infra/scripts/oidc-dual-host-smoke.mjs "$base_url" "$issuer_base_url"
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

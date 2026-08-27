import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const dockerEntrypoints = [
  'infra/deployment/smoke.sh',
  'infra/scripts/database-test.sh',
  'infra/scripts/docker-smoke.sh',
  'infra/scripts/docker-up.sh',
  'infra/scripts/realtime-smoke.sh',
  'verification/container-security.sh',
];

test('Docker build entrypoints run a free-storage preflight', async () => {
  for (const path of dockerEntrypoints) {
    const source = await readFile(path, 'utf8');
    assert.match(source, /docker_storage_preflight/u, path);
  }
});

test('disposable Docker entrypoints use exact lifecycle ownership and cleanup', async () => {
  for (const path of dockerEntrypoints.filter((path) => !path.endsWith('docker-up.sh'))) {
    const source = await readFile(path, 'utf8');
    assert.match(source, /docker_test_begin/u, path);
    assert.match(source, /docker_test_(?:register_image|configure_compose_images)/u, path);
    assert.match(source, /docker_test_finish/u, path);
    assert.match(source, /trap cleanup EXIT INT TERM/u, path);
    assert.match(source, /trap - EXIT INT TERM/u, path);
  }
});

test('automatic Docker scripts contain no broad prune operation', async () => {
  const paths = [
    ...dockerEntrypoints,
    'infra/scripts/docker-test-lifecycle.sh',
    'verification/docker-lifecycle-smoke.sh',
  ];
  for (const path of paths) {
    const source = await readFile(path, 'utf8');
    assert.doesNotMatch(source, /docker\s+system\s+prune/u, path);
    assert.doesNotMatch(source, /docker\s+image\s+prune(?:\s+[^\n]*)?\s+-a(?:\s|$)/u, path);
  }
});

test('nested realtime restarts retain the lifecycle ownership override', async () => {
  const source = await readFile('infra/scripts/realtime-smoke.mjs', 'utf8');
  assert.match(source, /infra\/testing\/compose\.lifecycle\.yaml/u);
});

test('deployment amd64 builds use Buildx and load exact local images', async () => {
  const source = await readFile('infra/deployment/smoke.sh', 'utf8');
  const imageSetBuilds = source.match(/build_image "\$1"/gu) ?? [];
  assert.equal(imageSetBuilds.length, 6);
  assert.match(source, /docker buildx version/u);
  assert.match(source, /docker buildx build --load --platform "\$platform"/u);
  assert.match(source, /build_image_set linux\/amd64/u);
  assert.match(source, /"\$architecture" != 'amd64'/u);
});

test('web container cross-build compiles natively with x64 runtime dependencies', async () => {
  const dockerfile = await readFile('apps/web/Dockerfile', 'utf8');
  const workspace = await readFile('pnpm-workspace.yaml', 'utf8');
  assert.match(dockerfile, /^FROM --platform=\$BUILDPLATFORM .+ AS build$/mu);
  assert.match(workspace, /supportedArchitectures:[\s\S]*- current[\s\S]*- linux/u);
  assert.match(workspace, /cpu:[\s\S]*- current[\s\S]*- x64/u);
});

test('lifecycle helper defaults to 20 GiB and supports diagnostic image retention', async () => {
  const source = await readFile('infra/scripts/docker-test-lifecycle.sh', 'utf8');
  assert.match(source, /KOVCHEG_DOCKER_MIN_FREE_GIB:-20/u);
  assert.match(source, /KOVCHEG_KEEP_TEST_IMAGES:-0/u);
  assert.match(source, /date -u \+%Y%m%dt%H%M%Sz/u);
  assert.match(source, /tr '\[:upper:\]' '\[:lower:\]'/u);
  assert.match(source, /No automatic cleanup was attempted/u);
  assert.match(source, /Refusing to remove image without exact current-run ownership/u);
});

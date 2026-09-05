import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { once } from 'node:events';
import test from 'node:test';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { parse } from 'yaml';

const dockerEntrypoints = [
  'infra/deployment/smoke.sh',
  'infra/scripts/database-test.sh',
  'infra/scripts/docker-smoke.sh',
  'infra/scripts/docker-up.sh',
  'infra/scripts/realtime-smoke.sh',
  'verification/container-security.sh',
  'verification/docker-lifecycle-smoke.sh',
];

test('Docker build entrypoints run a free-storage preflight', async () => {
  for (const path of dockerEntrypoints) {
    const source = await readFile(path, 'utf8');
    assert.match(source, /docker_storage_preflight/u, path);
    assert.match(source, /docker_buildx_preflight/u, path);
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
  assert.match(source, /docker_buildx_preflight/u);
  assert.match(source, /docker buildx build --load --platform "\$platform"/u);
  assert.match(source, /build_image_set linux\/amd64/u);
  assert.match(source, /"\$architecture" != 'amd64'/u);
});

test('Compose builds use BuildKit for cross-platform Dockerfiles', async () => {
  const source = await readFile('infra/scripts/compose.sh', 'utf8');
  assert.match(source, /export DOCKER_BUILDKIT=\$\{DOCKER_BUILDKIT:-1\}/u);
  assert.match(source, /export COMPOSE_DOCKER_CLI_BUILD=\$\{COMPOSE_DOCKER_CLI_BUILD:-1\}/u);
  assert.match(source, /export COMPOSE_BAKE=\$\{COMPOSE_BAKE:-true\}/u);
});

test('root Compose supplies the synthetic public OIDC client selectors to auth', async () => {
  const compose = await readFile('compose.yaml', 'utf8');
  assert.match(
    compose,
    /AUTH_OIDC_APPLICATION_CLIENT_ID: \$\{KOVCHEG_WEB_OIDC_CLIENT_ID:-kovcheg-local\}/u,
  );
  assert.match(
    compose,
    /AUTH_OIDC_APPLICATION_REDIRECT_URI: \$\{KOVCHEG_WEB_OIDC_REDIRECT_URI:-https:\/\/client\.invalid\/bff\/auth\/oidc\/callback\}/u,
  );
});

test('application environment selector is explicit across local and deployment entrypoints', async () => {
  const rootCompose = parse(await readFile('compose.yaml', 'utf8'), { merge: true });
  const deploymentCompose = parse(await readFile('infra/deployment/compose.yaml', 'utf8'), {
    merge: true,
  });
  const deploymentSelector = '${KOVCHEG_APP_ENV:?logical application environment is required}';

  for (const serviceName of ['api-1', 'api-2', 'auth', 'web', 'worker']) {
    assert.equal(rootCompose.services[serviceName].environment.KOVCHEG_APP_ENV, 'development');
    assert.equal(rootCompose.services[serviceName].environment.NODE_ENV, 'production');
    assert.equal(
      deploymentCompose.services[serviceName].environment.KOVCHEG_APP_ENV,
      deploymentSelector,
    );
    assert.equal(deploymentCompose.services[serviceName].environment.NODE_ENV, 'production');
  }
  for (const serviceName of ['migrate', 'migrate-test']) {
    assert.equal(
      deploymentCompose.services[serviceName].environment.KOVCHEG_APP_ENV,
      deploymentSelector,
    );
  }
  assert.equal(rootCompose.services.migrate.environment.KOVCHEG_APP_ENV, 'development');
  assert.equal(
    rootCompose.services['message-flow-test'].environment.KOVCHEG_APP_ENV,
    'development',
  );
  assert.equal(
    rootCompose.services['auth-integration-test'].environment.KOVCHEG_APP_ENV,
    'development',
  );

  const deploymentSmoke = await readFile('infra/deployment/smoke.sh', 'utf8');
  assert.match(deploymentSmoke, /export KOVCHEG_APP_ENV='staging'/u);
});

test('migration environment selector fails before external effects and accepts exact values', async () => {
  const fixture = await mkdtemp(path.join(tmpdir(), 'kovcheg-application-environment-'));
  const bin = path.join(fixture, 'bin');
  const migrations = path.join(fixture, 'migrations');
  const passwordFile = path.join(fixture, 'password');
  const calls = path.join(fixture, 'psql-calls');
  await mkdir(bin, { recursive: true });
  await mkdir(migrations, { recursive: true });
  await writeFile(passwordFile, 'synthetic-password\n', { mode: 0o600 });
  await writeFile(path.join(migrations, '0001_synthetic.sql'), 'SELECT 1;\n');
  await writeFile(
    path.join(bin, 'psql'),
    '#!/bin/sh\nprintf "called\\n" >>"$PSQL_CALLS_FILE"\nexit 0\n',
  );
  await writeFile(
    path.join(bin, 'sha256sum'),
    `#!/bin/sh\nprintf '${'a'.repeat(64)}  %s\\n' "$1"\n`,
  );
  await chmod(path.join(bin, 'psql'), 0o755);
  await chmod(path.join(bin, 'sha256sum'), 0o755);

  const baseEnvironment = {
    ...process.env,
    KOVCHEG_MIGRATION_ROOT: migrations,
    PATH: `${bin}:/usr/bin:/bin`,
    PGPASSWORD_FILE: passwordFile,
    PSQL_CALLS_FILE: calls,
  };

  for (const applicationEnvironment of [undefined, '', 'private-environment-marker', ' staging ']) {
    await rm(calls, { force: true });
    const environment = { ...baseEnvironment };
    if (applicationEnvironment === undefined) {
      delete environment.KOVCHEG_APP_ENV;
    } else {
      environment.KOVCHEG_APP_ENV = applicationEnvironment;
    }
    const result = spawnSync('sh', ['infra/postgres/migrate.sh'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      env: environment,
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /KOVCHEG_APP_ENV (?:is required|must be development)/u);
    assert.doesNotMatch(result.stderr, /private-environment-marker/u);
    await assert.rejects(readFile(calls, 'utf8'));
  }

  for (const applicationEnvironment of ['development', 'staging', 'production']) {
    await rm(calls, { force: true });
    const result = spawnSync('sh', ['infra/postgres/migrate.sh'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      env: { ...baseEnvironment, KOVCHEG_APP_ENV: applicationEnvironment },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal((await readFile(calls, 'utf8')).trim().split('\n').length, 3);
  }

  await rm(fixture, { force: true, recursive: true });
});

test('OIDC dual-host failures emit bounded allowlisted diagnostics without response data', async () => {
  const sensitiveMarker = 'must-not-appear-in-diagnostics';
  let observedHost = null;
  let observedForwardedHost = null;
  let observedForwardedProtocol = null;
  const server = createServer((request, response) => {
    observedHost = request.headers.host ?? null;
    observedForwardedHost = request.headers['x-forwarded-host'] ?? null;
    observedForwardedProtocol = request.headers['x-forwarded-proto'] ?? null;
    response.writeHead(503, { 'content-type': 'application/json' });
    response.end(
      JSON.stringify({
        code: 'a6.oidc-not-configured',
        nonce: sensitiveMarker,
        state: sensitiveMarker,
        token: sensitiveMarker,
        url: `https://upstream.invalid/callback?code=${sensitiveMarker}`,
      }),
    );
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.notEqual(address, null);
  assert.equal(typeof address, 'object');
  const loopback = `http://127.0.0.1:${address.port}`;
  const child = spawn(
    process.execPath,
    ['infra/scripts/oidc-dual-host-smoke.mjs', loopback, loopback],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        KOVCHEG_SMOKE_SESSION_TOKEN: 'synthetic-session',
        KOVCHEG_WEB_OIDC_ISSUER: 'https://issuer.invalid',
        KOVCHEG_WEB_OIDC_REDIRECT_URI: 'https://application.invalid/bff/auth/oidc/callback',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => {
    stdout += chunk;
  });
  child.stderr.setEncoding('utf8').on('data', (chunk) => {
    stderr += chunk;
  });
  const [exitCode] = await once(child, 'close');
  server.close();
  await once(server, 'close');

  assert.equal(exitCode, 1);
  assert.equal(stdout, '');
  assert.equal(observedHost, 'application.invalid');
  assert.equal(observedForwardedHost, null);
  assert.equal(observedForwardedProtocol, null);
  assert.match(
    stderr,
    /oidc-start response mismatch: expected=303 actual=503 bodyKind=json bodyBytes=\d+ errorCode=a6\.oidc-not-configured/u,
  );
  assert.doesNotMatch(stderr, new RegExp(sensitiveMarker, 'u'));
  assert.doesNotMatch(stderr, /upstream\.invalid/u);
  assert.doesNotMatch(stderr, /set-cookie|authorization|location/iu);
});

test('OIDC dual-host smoke validates the current application-session principal', async () => {
  const source = await readFile('infra/scripts/oidc-dual-host-smoke.mjs', 'utf8');
  assert.match(source, /principal\.contractVersion === 2/u);
  assert.match(source, /principal\.accountAccess === 'member'/u);
  assert.match(source, /principal\.accountStatus === 'active'/u);
  assert.match(source, /principal\.sessionStatus === 'active'/u);
  assert.match(source, /uuidExpression\.test\(principal\.userId\)/u);
  assert.match(source, /uuidExpression\.test\(principal\.sessionId\)/u);
  assert.doesNotMatch(source, /principal\.sessionActive/u);
  assert.doesNotMatch(source, /principal\.accountId/u);
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
  assert.match(source, /Docker Buildx is required before project-owned image builds/u);
  assert.match(source, /Refusing to remove image without exact current-run ownership/u);
  assert.match(source, /KOVCHEG_TEST_IMAGE_BASELINE_FILE/u);
  assert.match(source, /docker image ls --all --quiet --no-trunc/u);
  assert.match(source, /docker_test_list_owned_image_ids/u);
  assert.match(source, /KOVCHEG_DOCKER_TEST_LABEL_PROJECT=\$KOVCHEG_TEST_PROJECT/u);
  assert.match(source, /KOVCHEG_DOCKER_TEST_LABEL_PURPOSE=\$KOVCHEG_TEST_PURPOSE/u);
  assert.match(source, /KOVCHEG_DOCKER_TEST_LABEL_RUN=\$KOVCHEG_TEST_RUN_ID/u);
  assert.match(source, /KOVCHEG_DOCKER_TEST_LABEL_SOURCE=\$KOVCHEG_TEST_SOURCE_SHA/u);
  assert.match(source, /docker image rm "\$image_id"/u);
  assert.match(source, /Refusing to remove pre-existing image ID/u);
  assert.match(source, /Refusing to remove shared image ID with remaining tags/u);
  assert.match(source, /KOVCHEG_TEST_VOLUME_BASELINE_FILE/u);
  assert.match(source, /No unowned volume was removed automatically/u);
});

test('deployment verifier prefers Compose v2, falls back to v1, and fails without either', async () => {
  async function runWithTools({ dockerExit, legacyExit = 127 }) {
    const bin = await mkdtemp(path.join(tmpdir(), 'kovcheg-compose-selector-'));
    const log = path.join(bin, 'calls.log');
    const docker = path.join(bin, 'docker');
    await writeFile(
      docker,
      `#!/bin/sh\nprintf 'docker %s\\n' "$*" >>"${log}"\nexit ${dockerExit}\n`,
    );
    await chmod(docker, 0o755);
    const legacy = path.join(bin, 'docker-compose');
    await writeFile(
      legacy,
      `#!/bin/sh\nprintf 'docker-compose %s\\n' "$*" >>"${log}"\nexit ${legacyExit}\n`,
    );
    await chmod(legacy, 0o755);
    const result = spawnSync(process.execPath, ['infra/deployment/verify.mjs'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      env: { ...process.env, PATH: `${bin}:/usr/bin:/bin` },
    });
    const calls = await readFile(log, 'utf8').catch(() => '');
    await rm(bin, { force: true, recursive: true });
    const composeCalls = `${calls
      .split('\n')
      .filter((line) => line.startsWith('docker compose') || line.startsWith('docker-compose'))
      .join('\n')}\n`;
    return { composeCalls, result };
  }

  const v2 = await runWithTools({ dockerExit: 0 });
  assert.equal(v2.result.status, 0, v2.result.stderr);
  assert.equal(
    v2.composeCalls,
    'docker compose version\ndocker compose --file infra/deployment/compose.yaml config --quiet\n',
  );

  const v1 = await runWithTools({ dockerExit: 1, legacyExit: 0 });
  assert.equal(v1.result.status, 0, v1.result.stderr);
  assert.equal(
    v1.composeCalls,
    'docker compose version\ndocker-compose version\ndocker-compose --file infra/deployment/compose.yaml config --quiet\n',
  );

  const unavailable = await runWithTools({ dockerExit: 1 });
  assert.equal(unavailable.result.status, 1);
  assert.match(unavailable.result.stdout, /Compose TOOL_UNAVAILABLE/u);
  assert.equal(unavailable.composeCalls, 'docker compose version\ndocker-compose version\n');
});

test('PostgreSQL deployment image removes the unused vulnerable privilege helper', async () => {
  const dockerfile = await readFile('infra/postgres/Dockerfile', 'utf8');
  assert.match(dockerfile, /RUN rm -f \/usr\/local\/bin\/gosu/u);
  assert.match(dockerfile, /KOVCHEG_TEST_ROOT=\/opt\/kovcheg\/tests/u);
});

test('container security scans exact saved images without Docker runtime volumes', async () => {
  const source = await readFile('verification/container-security.sh', 'utf8');
  assert.match(source, /docker image save --output/u);
  assert.match(source, /trivy image \\\n+ {4}--input/u);
  assert.doesNotMatch(source, /trivy image \\\n+ {4}--scanners/u);
});

test('lifecycle regression removes foreign-container anonymous volumes', async () => {
  const source = await readFile('verification/docker-lifecycle-smoke.sh', 'utf8');
  const warmupIndex = source.indexOf('\ndocker_storage_preflight\n');
  const danglingBaselineIndex = source.indexOf('\ndangling_before=');
  const foreignTagIndex = source.indexOf('\ndocker image tag "$base_image" "$foreign_image"');
  assert.ok(warmupIndex >= 0);
  assert.ok(warmupIndex < danglingBaselineIndex);
  assert.ok(danglingBaselineIndex < foreignTagIndex);
  assert.doesNotMatch(source, /docker pull "\$base_image"/u);
  assert.match(source, /docker buildx build --load --platform linux\/amd64/u);
  assert.doesNotMatch(source, /docker build --platform linux\/amd64/u);
  assert.match(source, /docker rm --force --volumes "\$foreign_container"/u);
  assert.match(source, /volume_count_before=/u);
  assert.match(source, /volume_count_after=/u);
  assert.match(source, /Docker lifecycle regression changed volume count/u);
  assert.match(source, /docker commit "\$owned_commit_container"/u);
  assert.match(source, /docker_test_assert_image_ownership "\$owned_untagged_image"/u);
  assert.match(source, /\.RepoTags/u);
  assert.match(source, /Docker lifecycle regression changed dangling images/u);
});

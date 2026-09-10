import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { once } from 'node:events';
import test from 'node:test';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { parse } from 'yaml';

test('build-only producer binds exact archive inputs and retains only its six local images', async () => {
  const base = await realpath(await mkdtemp(path.join(tmpdir(), 'kovcheg-build-input-test-')));
  const checkout = path.join(base, 'checkout');
  const bin = path.join(base, 'bin');
  const mockState = path.join(base, 'mock.json');
  const calls = path.join(base, 'calls.jsonl');
  await mkdir(path.join(checkout, 'infra/deployment'), { recursive: true });
  await mkdir(path.join(checkout, 'infra/scripts'), { recursive: true });
  await mkdir(bin);
  for (const name of ['infra/deployment/smoke.sh', 'infra/scripts/docker-test-lifecycle.sh']) {
    await writeFile(path.join(checkout, name), await readFile(name));
  }
  await writeFile(path.join(checkout, '.gitignore'), '.local/\n.artifacts/\nignored.txt\n');
  for (const id of ['api', 'auth', 'web', 'worker', 'edge', 'postgres']) {
    const directory = path.join(checkout, ['edge', 'postgres'].includes(id) ? 'infra' : 'apps', id);
    await mkdir(directory, { recursive: true });
    await writeFile(
      path.join(directory, 'Dockerfile'),
      'FROM scratch AS runtime\n# synthetic ' + id + '\n',
    );
  }
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: checkout, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  git('init', '-q');
  git('config', 'user.name', 'Synthetic Fixture');
  git('config', 'user.email', 'fixture@source.invalid');
  git('remote', 'add', 'origin', 'https://github.com/planetic-labs/kovcheg.git');
  git('add', '.');
  git('commit', '-qm', 'Synthetic build fixture');
  await writeFile(path.join(checkout, 'ignored.txt'), 'must never enter the build context');
  const fakeDocker = String.raw`#!/usr/bin/env node
const fs=require('node:fs'),crypto=require('node:crypto'),cp=require('node:child_process'),path=require('node:path');
const a=process.argv.slice(2),file=process.env.BUILD_INPUT_MOCK_STATE;
fs.appendFileSync(process.env.BUILD_INPUT_MOCK_CALLS,JSON.stringify(a)+'\n');
let images=fs.existsSync(file)?JSON.parse(fs.readFileSync(file)): {};
const hash=b=>'sha256:'+crypto.createHash('sha256').update(b).digest('hex');
const save=()=>fs.writeFileSync(file,JSON.stringify(images));
const get=ref=>images[ref]??Object.values(images).find(x=>x.id===ref);
const print=x=>process.stdout.write(String(x)+'\n');
if(a[0]==='buildx'&&a[1]==='version') process.exit(0);
if(a[0]==='run'){print(30*1024*1024);process.exit(0);}
if(a[0]==='ps'||a[0]==='network'||a[0]==='volume') process.exit(0);
if(a[0]==='image'&&a[1]==='ls'){const ref=a.find(x=>x.startsWith('reference='));print(Object.values(images).filter(x=>!ref||x.tag===ref.slice(10)).map(x=>x.id).join('\n'));process.exit(0);}
if(a[0]==='buildx'&&a[1]==='build'){
  const data=fs.readFileSync(0),labels={};
  for(let i=0;i<a.length;i++)if(a[i]==='--label'){const eq=a[i+1].indexOf('=');labels[a[i+1].slice(0,eq)]=a[i+1].slice(eq+1);}
  if(labels['io.kovcheg.test.context-sha256']!==hash(data).slice(7))process.exit(7);
  const listed=cp.execFileSync('tar',['-tf','-'],{input:data,encoding:'utf8'});
  if(listed.includes('ignored.txt')||a.at(-1)!=='-'||a[a.indexOf('--platform')+1]!=='linux/amd64')process.exit(8);
  const tag=a[a.indexOf('--tag')+1],config=JSON.stringify({os:'linux',architecture:process.env.BUILD_INPUT_MOCK_FAILURE==='platform'?'arm64':'amd64',config:{Labels:labels}});
  const manifest=JSON.stringify({schemaVersion:2,config:{digest:hash(config),size:Buffer.byteLength(config)},layers:[]});
  const root=JSON.stringify({schemaVersion:2,manifests:[{digest:hash(manifest),size:Buffer.byteLength(manifest),platform:{os:'linux',architecture:'amd64'}}]});
  images[tag]={tag,id:hash(root),labels,config,manifest,root};save();process.exit(0);
}
if(a[0]==='image'&&a[1]==='save'){
  const image=get(a.at(-1)),out=a[a.indexOf('--output')+1],directory=fs.mkdtempSync(path.join(path.dirname(out),'mock-oci-'));
  fs.mkdirSync(path.join(directory,'blobs/sha256'),{recursive:true});
  for(const raw of [image.root,image.manifest,image.config])fs.writeFileSync(path.join(directory,'blobs/sha256',hash(raw).slice(7)),raw);
  fs.writeFileSync(path.join(directory,'index.json'),JSON.stringify({schemaVersion:2,manifests:[{digest:image.id,size:Buffer.byteLength(image.root)}]}));
  cp.execFileSync('tar',['-cf',out,'-C',directory,'index.json','blobs']);fs.rmSync(directory,{recursive:true});process.exit(0);
}
if(a[0]==='image'&&a[1]==='inspect'){
  const image=get(a.at(-1));if(!image)process.exit(1);
  const f=a.indexOf('--format');
  if(f<0)print(JSON.stringify([{Id:image.id,Architecture:'amd64',Config:{Labels:image.labels}}]));
  else {const format=a[f+1],label=/index .Config.Labels "([^"]+)"/u.exec(format);print(label?image.labels[label[1]]:format==='{{.Id}}'?image.id:format==='{{.Architecture}}'?'amd64':'');}
  process.exit(0);
}
if(a[0]==='image'&&a[1]==='rm'){for(const [k,v] of Object.entries(images))if(k===a[2]||v.id===a[2])delete images[k];save();process.exit(0);}
process.stderr.write('Unexpected mock Docker operation\n');process.exit(9);
`;
  await writeFile(path.join(bin, 'docker'), fakeDocker, { mode: 0o755 });
  const environment = {
    ...process.env,
    PATH: bin + path.delimiter + process.env.PATH,
    BUILD_INPUT_MOCK_STATE: mockState,
    BUILD_INPUT_MOCK_CALLS: calls,
  };
  const invoke = (output, extra = {}) =>
    spawnSync('sh', ['infra/deployment/smoke.sh', '--build-only', output], {
      cwd: checkout,
      encoding: 'utf8',
      env: { ...environment, ...extra },
      timeout: 60_000,
    });
  try {
    const output = path.join(base, 'success');
    const result = invoke(output);
    assert.equal(result.status, 0, result.stderr);
    const input = JSON.parse(await readFile(path.join(output, 'local-build-input.json'), 'utf8'));
    assert.deepEqual(Object.keys(input).sort(), ['kind', 'new', 'old']);
    assert.equal(input.kind, 'local-installed-update-builds-v1');
    assert.equal(input.old, null);
    assert.equal(input.new.source_checkout, await realpath(checkout));
    assert.equal(input.new.source_commit, git('rev-parse', 'HEAD'));
    assert.equal(input.new.source_tree, git('rev-parse', 'HEAD^{tree}'));
    assert.deepEqual(
      input.new.artifacts.map((x) => x.artifact_id),
      ['api', 'auth', 'web', 'worker', 'edge', 'postgres'],
    );
    for (const item of input.new.artifacts) {
      assert.deepEqual(Object.keys(item).sort(), [
        'artifact_id',
        'context',
        'context_archive_sha256',
        'context_tree',
        'dockerfile',
        'dockerfile_sha256',
        'image_archive',
        'image_archive_sha256',
        'image_config_digest',
        'index_digest',
        'platform_manifest_digest',
      ]);
      for (const name of ['context_archive_sha256', 'dockerfile_sha256', 'image_archive_sha256'])
        assert.match(item[name], /^[a-f0-9]{64}$/u);
      for (const name of ['index_digest', 'platform_manifest_digest', 'image_config_digest'])
        assert.match(item[name], /^sha256:[a-f0-9]{64}$/u);
      const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
      assert.equal(item.image_archive_sha256, hash(await readFile(item.image_archive)));
      const archiveRef =
        item.context === '.'
          ? input.new.source_commit
          : input.new.source_commit + ':' + item.context;
      const contextBytes = spawnSync(
        'git',
        ['archive', '--format=tar', '--mtime=1970-01-01T00:00:00Z', archiveRef],
        { cwd: checkout },
      );
      assert.equal(contextBytes.status, 0);
      assert.equal(item.context_archive_sha256, hash(contextBytes.stdout));
      for (const name of ['index_digest', 'platform_manifest_digest', 'image_config_digest']) {
        const blob = spawnSync('tar', [
          '-xOf',
          item.image_archive,
          'blobs/sha256/' + item[name].slice(7),
        ]);
        assert.equal(blob.status, 0);
        assert.equal(item[name], 'sha256:' + hash(blob.stdout));
      }
    }
    const operations = (await readFile(calls, 'utf8')).trim().split('\n').map(JSON.parse);
    assert.equal(operations.filter((a) => a[0] === 'buildx' && a[1] === 'build').length, 6);
    assert.equal(operations.filter((a) => a[0] === 'image' && a[1] === 'save').length, 6);
    assert(
      !operations.some(
        (a) =>
          a.includes('compose') || a.includes('push') || a.includes('login') || a.includes('load'),
      ),
    );
    assert.equal(
      operations.filter((a) => a[0] === 'run' || a[0] === 'rm' || a[1] === 'rm').length,
      0,
    );
    const retained = JSON.parse(await readFile(mockState, 'utf8'));
    assert.equal(Object.keys(retained).length, 6);
    assert.equal(git('status', '--porcelain', '--untracked-files=all'), '');
    const before = await readFile(calls, 'utf8');
    assert.notEqual(invoke(output).status, 0);
    assert.equal(await readFile(calls, 'utf8'), before);
    await writeFile(path.join(checkout, 'untracked.txt'), 'synthetic dirty source');
    assert.notEqual(invoke(path.join(base, 'dirty')).status, 0);
    assert.equal(await readFile(calls, 'utf8'), before);
    await rm(path.join(checkout, 'untracked.txt'));
    const failure = invoke(path.join(base, 'wrong-platform'), {
      BUILD_INPUT_MOCK_FAILURE: 'platform',
    });
    assert.notEqual(failure.status, 0);
    await assert.rejects(readFile(path.join(base, 'wrong-platform/local-build-input.json')));
    assert.equal(Object.keys(JSON.parse(await readFile(mockState, 'utf8'))).length, 7);
    assert(
      (await readFile(path.join(base, 'wrong-platform/lifecycle-images.tsv'), 'utf8')).length > 0,
    );
    assert.equal(git('status', '--porcelain', '--untracked-files=all'), '');
    const afterFailure = JSON.parse(await readFile(mockState, 'utf8'));
    for (const [tag, record] of Object.entries(retained))
      assert.deepEqual(afterFailure[tag], record);
    const afterCalls = await readFile(calls, 'utf8');
    await symlink('ignored.txt', path.join(checkout, 'context-link'));
    git('add', 'context-link');
    git('commit', '-qm', 'Synthetic unsupported context link');
    assert.notEqual(invoke(path.join(base, 'context-link-output')).status, 0);
    assert.equal(await readFile(calls, 'utf8'), afterCalls);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

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

test('deployment auth alone has dedicated outbound bridge with lifecycle ownership', async () => {
  const compose = parse(await readFile('infra/deployment/compose.yaml', 'utf8'), { merge: true });
  const lifecycle = parse(await readFile('infra/deployment/compose.lifecycle.yaml', 'utf8'));
  assert.deepEqual(compose.networks['auth-egress'], { driver: 'bridge', internal: false });
  assert.deepEqual(compose.services.auth.networks, ['service-internal', 'auth-egress']);
  assert.equal(compose.services.auth.ports, undefined);
  assert.equal(compose.networks['service-internal'].internal, true);
  assert.deepEqual(compose.services.postgres.networks, ['service-internal']);
  for (const [name, service] of Object.entries(compose.services)) {
    if (name !== 'auth') assert.ok(!service.networks.includes('auth-egress'), name);
  }
  assert.deepEqual(
    lifecycle.networks['auth-egress'].labels,
    lifecycle.networks['service-internal'].labels,
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

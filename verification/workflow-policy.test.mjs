import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { parse } from 'yaml';

import { repositoryRoot } from './lib.mjs';
import { analyzeWorkflow } from './workflow-policy-core.mjs';

const fixtureDirectory = path.join(repositoryRoot, 'verification/fixtures/workflow-policy');
const ciWorkflowPath = path.join(repositoryRoot, '.github/workflows/ci.yml');
const ciWorkflowContents = await readFile(ciWorkflowPath, 'utf8');
const ciWorkflow = parse(ciWorkflowContents);
const deploymentSmokeContents = await readFile(
  path.join(repositoryRoot, 'infra/deployment/smoke.sh'),
  'utf8',
);
const publicationWorkflowPath = path.join(
  repositoryRoot,
  '.github/workflows/publish-ghcr-images.yml',
);
const publicationWorkflowContents = await readFile(publicationWorkflowPath, 'utf8');
const publicationWorkflow = parse(publicationWorkflowContents);
const publicationImages = [
  {
    service: 'api',
    package: 'ghcr.io/planetic-labs/kovcheg-api',
    context: '.',
    dockerfile: 'apps/api/Dockerfile',
  },
  {
    service: 'auth',
    package: 'ghcr.io/planetic-labs/kovcheg-auth',
    context: '.',
    dockerfile: 'apps/auth/Dockerfile',
  },
  {
    service: 'web',
    package: 'ghcr.io/planetic-labs/kovcheg-web',
    context: '.',
    dockerfile: 'apps/web/Dockerfile',
  },
  {
    service: 'worker',
    package: 'ghcr.io/planetic-labs/kovcheg-worker',
    context: '.',
    dockerfile: 'apps/worker/Dockerfile',
  },
  {
    service: 'edge',
    package: 'ghcr.io/planetic-labs/kovcheg-edge',
    context: 'infra/edge',
    dockerfile: 'infra/edge/Dockerfile',
  },
  {
    service: 'postgres',
    package: 'ghcr.io/planetic-labs/kovcheg-postgres',
    context: 'infra/postgres',
    dockerfile: 'infra/postgres/Dockerfile',
  },
];
const sourceSha = 'a'.repeat(40);

function extractValidator(run, name) {
  const start = `// BEGIN ${name}_VALIDATOR`;
  const end = `// END ${name}_VALIDATOR`;
  const startIndex = run.indexOf(start);
  const endIndex = run.indexOf(end);
  assert.notEqual(startIndex, -1, `${name} validator start marker is missing`);
  assert.notEqual(endIndex, -1, `${name} validator end marker is missing`);
  return run.slice(startIndex + start.length, endIndex);
}

function runValidator({ directory, script, env = {} }) {
  return spawnSync(process.execPath, ['--input-type=module'], {
    cwd: directory,
    encoding: 'utf8',
    env: {
      ...process.env,
      SOURCE_SHA: sourceSha,
      SOURCE_TREE: 'b'.repeat(40),
      WORKFLOW_SHA: sourceSha,
      MODE: 'WORKING',
      ...env,
    },
    input: script,
  });
}

function writeJsonRecords(directory, records) {
  mkdirSync(directory, { recursive: true });
  for (const [index, record] of records.entries()) {
    writeFileSync(path.join(directory, `${index}.json`), JSON.stringify(record));
  }
}

function inventoryRecord(image, index, state) {
  const digest = state === 'existing' ? `sha256:${(index + 1).toString(16).repeat(64)}` : null;
  return {
    service: image.service,
    package: image.package,
    state,
    digest,
    sourceSha,
    navigationTag: `sha-${sourceSha}`,
    platform: 'linux/amd64',
    deploymentRef: digest ? `${image.package}@${digest}` : null,
  };
}

function mappingRecord(image, index, mode = 'WORKING') {
  const digest = `sha256:${(index + 1).toString(16).repeat(64)}`;
  return {
    service: image.service,
    package: image.package,
    digest,
    sourceSha,
    sourceTree: 'b'.repeat(40),
    trustedWorkflowSha: sourceSha,
    navigationTag: `sha-${sourceSha}`,
    platform: 'linux/amd64',
    deploymentRef: `${image.package}@${digest}`,
    publicationState: index % 2 === 0 ? 'published' : 'adopted',
    attestation: {
      predicateType:
        mode === 'TRIAL'
          ? 'https://github.com/planetic-labs/kovcheg/attestations/source-binding/v1'
          : 'https://slsa.dev/provenance/v1',
      id: `attestation-${index}`,
      url: `https://github.com/planetic-labs/kovcheg/attestations/${index}`,
    },
  };
}

async function analyze(fixture) {
  return analyzeWorkflow({
    contents: await readFile(path.join(fixtureDirectory, fixture), 'utf8'),
    file: fixture,
    permissionAllowlist: { contents: 'read' },
  });
}

const { validateSource, sourceGitProvider } = await import(
  `data:text/javascript,${encodeURIComponent(extractValidator(publicationWorkflow.jobs['validate-source'].steps[0].run, 'SOURCE'))}`
);
const { sourcePredicate } = await import(
  `data:text/javascript,${encodeURIComponent(extractValidator(publicationWorkflow.jobs.publish.steps.find((s) => s.name === 'Write candidate and trusted workflow provenance').run, 'PROVENANCE'))}`
);

test('source gate checks bounded linear Git history, exact paths and expiry', async (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), 'kovcheg-trial-source-'));
  const git = (args, input) => {
    const result = spawnSync('git', ['-C', directory, ...args], {
      input,
      encoding: 'utf8',
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: 'Synthetic',
        GIT_COMMITTER_NAME: 'Synthetic',
        GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
        GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
      },
    });
    if (result.status !== 0) throw new Error('synthetic Git read failed');
    return result.stdout;
  };
  try {
    git(['init', '--bare']);
    const makeTree = (entries) => {
      const groups = new Map();
      for (const [name, content] of Object.entries(entries)) {
        const [part, ...rest] = name.split('/');
        if (rest.length) {
          groups.set(part, { ...groups.get(part), [rest.join('/')]: content });
        } else groups.set(part, content);
      }
      return git(
        ['mktree', '-z'],
        [...groups]
          .map(([name, value]) =>
            typeof value === 'string'
              ? `100644 blob ${git(['hash-object', '-w', '--stdin'], value).trim()}\t${name}\0`
              : `040000 tree ${makeTree(value)}\t${name}\0`,
          )
          .join(''),
      ).trim();
    };
    const commit = (entries, parents = []) =>
      git([
        'commit-tree',
        makeTree(entries),
        ...parents.flatMap((parent) => ['-p', parent]),
        '-m',
        'synthetic fixture',
      ]).trim();
    const baseEntries = { 'allowed.txt': 'one' };
    const base = commit(baseEntries);
    const candidate = commit({ 'allowed.txt': 'two' }, [base]);
    const outside = commit({ 'forbidden.txt': 'three' }, [base]);
    const unrelated = commit({ 'allowed.txt': 'unrelated' });
    const tree = (sha) => git(['rev-parse', `${sha}^{tree}`]).trim();
    const scope = {
      branch: 'refs/heads/trial-fixture',
      baseSha: base,
      baseTree: tree(base),
      candidateTree: tree(candidate),
      allowedPaths: ['allowed.txt'],
      expiresAt: '2030-01-01T01:00:00Z',
      trustedWorkflowSha: base,
    };
    const env = {
      MODE: 'TRIAL',
      REPOSITORY: 'planetic-labs/kovcheg',
      SOURCE_SHA: candidate,
      WORKFLOW_REF: 'refs/heads/main',
      WORKFLOW_SHA: base,
      RUN_ATTEMPT: '1',
      TRIAL_SCOPE: JSON.stringify(scope),
    };
    const providerFor = (head) =>
      sourceGitProvider((args) => {
        if (args[0] === 'fetch') return '';
        if (args[0] === 'ls-remote') {
          const ref = args.at(-1);
          return `${ref === 'refs/heads/main' ? base : head}\t${ref}\n`;
        }
        return git(args);
      });
    const provider = providerFor(candidate);
    const now = Date.parse('2030-01-01T00:00:00Z');
    assert.deepEqual(
      validateSource(env, provider, () => now).matrix.include,
      publicationImages.slice(0, 5),
    );
    assert.deepEqual(
      validateSource(
        { ...env, MODE: 'WORKING', SOURCE_SHA: base, TRIAL_SCOPE: '' },
        provider,
        () => now,
      ).matrix.include,
      publicationImages,
    );
    for (const [name, changes, scopeChanges, providerChanges, time] of [
      ['fork', { REPOSITORY: 'fork/kovcheg' }],
      ['workflow ref', { WORKFLOW_REF: 'refs/heads/candidate' }],
      ['wrong SHA', { SOURCE_SHA: 'a'.repeat(40) }],
      ['abbreviated SHA', { SOURCE_SHA: candidate.slice(0, 8) }],
      ['wrong tree', {}, { candidateTree: 'a'.repeat(40) }],
      ['wrong base tree', {}, { baseTree: 'a'.repeat(40) }],
      ['unrelated base', {}, { baseSha: unrelated, baseTree: tree(unrelated) }],
      ['branch moved', {}, {}, { head: (ref) => (ref === 'refs/heads/main' ? base : outside) }],
      ['main moved', {}, {}, { head: () => candidate }],
      ['arbitrary ref', {}, { branch: 'refs/pull/1/head' }],
      ['branch expression', {}, { branch: 'refs/heads/a;exit' }],
      ['path traversal', {}, { allowedPaths: ['../'] }],
      ['workflow path', {}, { allowedPaths: ['.github/'] }],
      ['scope mismatch', {}, { allowedPaths: ['other.txt'] }],
      [
        'scope changed file',
        { SOURCE_SHA: outside },
        { candidateTree: tree(outside) },
        providerFor(outside),
      ],
      ['expired', {}, {}, {}, now + 3600000],
      ['bad TTL', {}, { expiresAt: 'tomorrow' }],
      ['trusted workflow mismatch', {}, { trustedWorkflowSha: candidate }],
      ['rerun', { RUN_ATTEMPT: '2' }],
      ['extra authority input', {}, { authority_hash: 'not-authority' }],
      ['WORKING candidate', { MODE: 'WORKING', TRIAL_SCOPE: '' }],
      ['WORKING unexpected scope', { MODE: 'WORKING', SOURCE_SHA: base }],
      ['invalid mode', { MODE: 'OTHER' }],
    ])
      await t.test(name, () => {
        const attempt = {
          ...env,
          TRIAL_SCOPE: JSON.stringify({ ...scope, ...scopeChanges }),
          ...changes,
        };
        assert.throws(
          () => validateSource(attempt, { ...provider, ...providerChanges }, () => time ?? now),
          /rejected/,
        );
      });
    const checkHead = (head, allowedPaths = scope.allowedPaths) =>
      validateSource(
        {
          ...env,
          SOURCE_SHA: head,
          TRIAL_SCOPE: JSON.stringify({ ...scope, candidateTree: tree(head), allowedPaths }),
        },
        providerFor(head),
        () => now,
      );
    await t.test('out-of-scope then revert is rejected', () => {
      const reverted = commit(baseEntries, [outside]);
      assert.equal(tree(reverted), tree(base));
      assert.throws(() => checkHead(reverted), /rejected/);
    });
    await t.test('merge history is rejected', () => {
      const merged = commit({ 'allowed.txt': 'merged' }, [candidate, outside]);
      assert.throws(() => checkHead(merged), /rejected/);
    });
    await t.test('exact 64-commit bound includes base', () => {
      let head = candidate;
      for (let index = 2; index <= 63; index++)
        head = commit({ 'allowed.txt': String(index) }, [head]);
      assert.equal(checkHead(head).source_sha, head);
      assert.throws(() => checkHead(commit({ 'allowed.txt': '64' }, [head])), /rejected/);
    });
    for (const name of [' allowed.txt', 'allowed.txt ', '\tallowed.txt', 'allowed.txt\n']) {
      await t.test('NUL-delimited whitespace path remains exact: ' + JSON.stringify(name), () => {
        const head = commit({ ...baseEntries, [name]: 'changed' }, [base]);
        assert.ok(providerFor(head).paths(base, head).includes(name));
        assert.throws(() => checkHead(head), /rejected/);
      });
    }
    for (const name of [
      'infra/postgres/Dockerfile',
      'infra/postgres/migrations/0099.sql',
      '.gitattributes',
      'infra/.gitattributes',
      '.github/workflows/publish-ghcr-images.yml',
    ]) {
      await t.test('protected input and its revert remain rejected: ' + name, () => {
        const head = commit({ ...baseEntries, [name]: 'changed' }, [base]);
        const reverted = commit(baseEntries, [head]);
        for (const value of [head, reverted]) {
          assert.throws(
            () => checkHead(value, ['infra/', '.gitattributes', 'allowed.txt']),
            /rejected/,
          );
        }
      });
    }
    await t.test('expiry during provider reads is rejected at completion', () => {
      let current = now;
      const slow = {
        ...provider,
        paths: (...args) => {
          const result = provider.paths(...args);
          current += 3600000;
          return result;
        },
      };
      assert.throws(() => validateSource(env, slow, () => current), /rejected/);
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('privileged jobs use only trusted code and attested candidate binding', () => {
  const build = publicationWorkflow.jobs.build;
  const publish = publicationWorkflow.jobs.publish;
  const gitWrapper = publicationWorkflow.jobs['validate-source'].steps[0].run
    .split('\n')
    .find((line) => line.startsWith('const git ='));
  assert.ok(gitWrapper);
  assert.doesNotMatch(gitWrapper, /\.trim\(/);
  assert.deepEqual(build.permissions, { contents: 'read' });
  assert.equal(
    build.steps.find((s) => s.uses?.startsWith('actions/checkout@')).with['persist-credentials'],
    false,
  );
  assert.ok(
    build.steps.some((s) => s.name === 'Assert the build checkout matches the validated source'),
  );
  assert.ok(
    !build.steps.some(
      (s) => s.uses?.startsWith('docker/login-action@') || s.uses?.startsWith('actions/attest'),
    ),
  );
  assert.ok(
    !publish.steps.some(
      (s) =>
        s.uses?.startsWith('actions/checkout@') ||
        s.uses?.startsWith('./') ||
        /docker (run|exec|build)\b|docker buildx build\b|pnpm |npm /.test(s.run ?? ''),
    ),
  );
  for (const id of ['source', 'pre_push', 'pre_attest']) {
    assert.equal(
      publish.steps.find((s) => s.id === id).run,
      publicationWorkflow.jobs['validate-source'].steps[0].run,
    );
  }
  const attest = publish.steps.find((s) => s.id === 'attest');
  assert.equal(
    attest.with['predicate-path'],
    "${{ inputs.mode == 'TRIAL' && 'source-predicate.json' || '' }}",
  );
  assert.equal(
    attest.with['predicate-type'],
    "${{ inputs.mode == 'TRIAL' && 'https://github.com/planetic-labs/kovcheg/attestations/source-binding/v1' || '' }}",
  );
  assert.equal(
    publish.steps.find((s) => s.name === 'Write candidate and trusted workflow provenance').if,
    "inputs.mode == 'TRIAL'",
  );
  const env = {
    REPOSITORY: 'planetic-labs/kovcheg',
    SOURCE_SHA: sourceSha,
    SOURCE_TREE: 'b'.repeat(40),
    WORKFLOW_SHA: 'c'.repeat(40),
    DIGEST: `sha256:${'d'.repeat(64)}`,
    PACKAGE: publicationImages[0].package,
    MODE: 'TRIAL',
    GITHUB_RUN_ID: '42',
    RUN_ATTEMPT: '1',
  };
  const predicate = sourcePredicate(env);
  assert.equal(predicate.source.commit, sourceSha);
  assert.equal(predicate.source.tree, env.SOURCE_TREE);
  assert.equal(predicate.workflow.commit, env.WORKFLOW_SHA);
  assert.notEqual(predicate.source.commit, predicate.workflow.commit);
  assert.equal(predicate.image.digest, env.DIGEST);
  assert.throws(() => sourcePredicate({ ...env, DIGEST: 'mutable-tag' }), /invalid/);
  for (const change of [
    { MODE: 'WORKING' },
    { RUN_ATTEMPT: '2' },
    { GITHUB_RUN_ID: '' },
    { PACKAGE: publicationImages[5].package },
    { PACKAGE: env.PACKAGE.replace('ghcr.io', 'ghcrXio') },
  ]) {
    assert.throws(() => sourcePredicate({ ...env, ...change }), /invalid/);
  }
});

test('TRIAL inventory and aggregate accept exactly five images and reject PostgreSQL', () => {
  const inventory = extractValidator(
    publicationWorkflow.jobs.inventory.steps.find((s) => s.name.startsWith('Classify')).run,
    'INVENTORY',
  );
  const aggregate = extractValidator(
    publicationWorkflow.jobs.aggregate.steps.find((s) => s.name.startsWith('Validate')).run,
    'AGGREGATE',
  );
  for (const count of [5, 6]) {
    const directory = mkdtempSync(path.join(tmpdir(), 'kovcheg-trial-map-'));
    try {
      writeJsonRecords(
        path.join(directory, 'publication-inventory'),
        publicationImages.slice(0, count).map((v, i) => inventoryRecord(v, i, 'existing')),
      );
      writeJsonRecords(
        path.join(directory, 'publication-mappings'),
        publicationImages.slice(0, count).map((v, i) => mappingRecord(v, i, 'TRIAL')),
      );
      for (const script of [inventory, aggregate]) {
        const result = runValidator({ directory, script, env: { MODE: 'TRIAL' } });
        assert.equal(result.status === 0, count === 5, result.stderr);
      }
      if (count === 5)
        assert.equal(
          JSON.parse(readFileSync(path.join(directory, 'ghcr-five-image-mapping.json'))).imageCount,
          5,
        );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test('publication shell mocks first push, resume, conflicts and final expiry without Docker', async (t) => {
  const step = publicationWorkflow.jobs.publish.steps.find((s) => s.id === 'image');
  const script = step.run;
  assert.equal(step.env.TRIAL_EXPIRES_AT, '$' + '{{ steps.pre_push.outputs.expires_at }}');
  assert.match(script, /END PUSH_TTL_VALIDATOR\nNODE\n\s*push_output=/);
  const directory = mkdtempSync(path.join(tmpdir(), 'kovcheg-publication-mock-'));
  try {
    const digest = 'sha256:' + 'd'.repeat(64);
    const docker =
      '#!' +
      process.execPath +
      '\n' +
      '(' +
      function mockDocker(fs) {
        const args = process.argv.slice(2);
        fs.appendFileSync(process.env.MOCK_LOG, args.slice(0, 2).join(' ') + '\n');
        const labels = {
          'org.opencontainers.image.source': 'https://github.com/planetic-labs/kovcheg',
          'org.opencontainers.image.revision': process.env.SOURCE_SHA,
        };
        if (args[0] === 'push') {
          process.stdout.write('digest: ' + process.env.MOCK_DIGEST);
          process.exit(0);
        }
        if (args[0] === 'image') {
          if (args.includes('{{.Architecture}}')) process.stdout.write(process.env.MOCK_ARCH);
          else if (args.at(-1).includes('org.opencontainers.image.source'))
            process.stdout.write(labels['org.opencontainers.image.source']);
          else if (args.at(-1).includes('org.opencontainers.image.revision'))
            process.stdout.write(process.env.MOCK_REVISION);
          else process.exit(98);
        } else if (args.includes('{{json .Manifest}}')) {
          process.stdout.write(JSON.stringify({ digest: process.env.MOCK_DIGEST }));
        } else if (args.includes('{{json .Image}}')) {
          process.stdout.write(
            JSON.stringify({
              os: 'linux',
              architecture: process.env.MOCK_ARCH,
              config: { Labels: labels },
            }),
          );
        } else if (args[0] === 'buildx' && args[1] === 'imagetools') {
          if (process.env.MOCK_REMOTE === 'absent') {
            process.stderr.write('manifest unknown');
            process.exit(1);
          }
          if (process.env.MOCK_REMOTE === 'ambiguous') {
            process.stderr.write('registry unavailable');
            process.exit(1);
          }
        } else process.exit(98);
      }.toString() +
      ")(require('node:fs'));";
    writeFileSync(path.join(directory, 'docker'), docker, { mode: 0o700 });
    writeFileSync(
      path.join(directory, 'git'),
      '#!/bin/sh\nprintf "%s\\trefs/heads/main\\n" "$WORKFLOW_SHA"\n',
      { mode: 0o700 },
    );
    for (const [name, overrides, success, pushes] of [
      ['WORKING first push', {}, true, 1],
      ['TRIAL first push', { MODE: 'TRIAL', TRIAL_EXPIRES_AT: '2999-01-01T00:00:00Z' }, true, 1],
      ['tag appeared', { MOCK_REMOTE: 'existing' }, false, 0],
      ['registry unavailable', { MOCK_REMOTE: 'ambiguous' }, false, 0],
      ['existing adopted', { INVENTORY_STATE: 'existing' }, true, 0],
      [
        'existing changed',
        { INVENTORY_STATE: 'existing', INVENTORY_DIGEST: 'sha256:' + 'e'.repeat(64) },
        false,
        0,
      ],
      ['wrong architecture', { MOCK_ARCH: 'arm64' }, false, 0],
      ['wrong revision', { MOCK_REVISION: 'b'.repeat(40) }, false, 0],
      [
        'expired before push',
        { MODE: 'TRIAL', TRIAL_EXPIRES_AT: '2000-01-01T00:00:00Z' },
        false,
        0,
      ],
      ['missing expiry', { MODE: 'TRIAL' }, false, 0],
      ['invalid mode', { MODE: 'OTHER' }, false, 0],
    ])
      await t.test(name, () => {
        const log = path.join(directory, 'calls');
        writeFileSync(log, '');
        const result = spawnSync('sh', ['-c', script], {
          cwd: directory,
          encoding: 'utf8',
          env: {
            ...process.env,
            PATH: directory + ':' + process.env.PATH,
            SOURCE_SHA: sourceSha,
            WORKFLOW_SHA: 'c'.repeat(40),
            MODE: 'WORKING',
            TRIAL_EXPIRES_AT: '',
            REPOSITORY: 'planetic-labs/kovcheg',
            SERVICE: 'api',
            PACKAGE: publicationImages[0].package,
            INVENTORY_STATE: 'absent',
            INVENTORY_DIGEST: digest,
            MOCK_DIGEST: digest,
            MOCK_REMOTE: 'absent',
            MOCK_ARCH: 'amd64',
            MOCK_REVISION: sourceSha,
            MOCK_LOG: log,
            GITHUB_OUTPUT: path.join(directory, 'output'),
            ...overrides,
          },
        });
        assert.equal(result.status === 0, success, result.stderr);
        const calls = readFileSync(log, 'utf8');
        assert.equal((calls.match(/^push /gm) ?? []).length, pushes);
        if (name === 'expired before push') {
          assert.match(calls, /image inspect/);
          assert.match(result.stderr, /validity window expired/);
        }
      });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('WORKING SLSA and TRIAL custom attestations cannot be substituted in aggregates', () => {
  const script = extractValidator(
    publicationWorkflow.jobs.aggregate.steps.find((s) => s.name.startsWith('Validate')).run,
    'AGGREGATE',
  );
  for (const mode of ['WORKING', 'TRIAL']) {
    for (const mismatch of [false, true]) {
      const directory = mkdtempSync(path.join(tmpdir(), 'kovcheg-attestation-mode-'));
      try {
        const records = publicationImages
          .slice(0, mode === 'TRIAL' ? 5 : 6)
          .map((v, i) => mappingRecord(v, i, mode));
        if (mismatch)
          records[0].attestation.predicateType =
            mode === 'TRIAL'
              ? 'https://slsa.dev/provenance/v1'
              : 'https://github.com/planetic-labs/kovcheg/attestations/source-binding/v1';
        writeJsonRecords(path.join(directory, 'publication-mappings'), records);
        const result = runValidator({ directory, script, env: { MODE: mode } });
        assert.equal(result.status === 0, !mismatch, result.stderr);
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    }
  }
});

test('parsed traversal accepts pinned step, job, and container uses', async () => {
  const report = await analyze('valid.fixture');
  assert.deepEqual(report.findings, []);
  assert.equal(report.uses.length, 3);
  assert.deepEqual(report.pinnedUses.map((use) => use.kind).sort(), [
    'container',
    'repository',
    'repository',
  ]);
  assert.ok(report.uses.some((use) => use.path.endsWith('.steps[0].uses')));
  assert.ok(report.uses.some((use) => use.path.endsWith('.reusable.uses')));
});

test('all unpinned step and job uses are rejected', async () => {
  const report = await analyze('unpinned.fixture');
  assert.equal(report.uses.length, 3);
  assert.equal(
    report.findings.filter((finding) => finding.rule === 'immutable-action-pin').length,
    3,
  );
});

test('permissions must match the explicit minimal allowlist', async () => {
  const report = await analyze('excess-permissions.fixture');
  assert.ok(report.findings.some((finding) => finding.rule === 'permissions-allowlist'));
});

test('CI runs exact-head native deployment smoke with bounded read-only lifecycle ownership', () => {
  const expectedSha = '${{ github.event.pull_request.head.sha || github.sha }}';
  assert.deepEqual(ciWorkflow.permissions, { contents: 'read' });
  assert.deepEqual(ciWorkflow.concurrency, {
    group: 'ci-${{ github.workflow }}-' + expectedSha,
    'cancel-in-progress': false,
  });

  const job = ciWorkflow.jobs['native-deployment-smoke'];
  assert.equal(job.name, 'Native deployment smoke');
  assert.equal(job['runs-on'], 'ubuntu-latest');
  assert.equal(job['timeout-minutes'], 45);
  assert.deepEqual(job.permissions, { contents: 'read' });
  assert.equal(job.env.EXPECTED_SHA, expectedSha);

  const checkout = job.steps.find((step) => step.name === 'Check out exact source commit');
  const provenance = job.steps.find((step) => step.name === 'Assert exact clean source provenance');
  const smoke = job.steps.find((step) => step.name === 'Run exact native deployment smoke');
  const finalReadback = job.steps.find(
    (step) => step.name === 'Confirm exact source remains clean',
  );
  assert.equal(checkout.with.ref, '${{ env.EXPECTED_SHA }}');
  assert.equal(checkout.with['fetch-depth'], 1);
  assert.equal(checkout.with['persist-credentials'], false);
  assert.match(provenance.run, /git rev-parse HEAD/);
  assert.match(provenance.run, /git rev-parse HEAD\^\{tree\}/);
  assert.match(provenance.run, /actual_sha" != "\$EXPECTED_SHA/);
  assert.match(provenance.run, /\^\[0-9a-f\]\{40\}\$/);
  assert.match(provenance.run, /git status --porcelain --untracked-files=normal/);
  assert.equal(smoke.run, 'corepack pnpm deployment:smoke');
  assert.equal(finalReadback.if, '${{ always() }}');
  assert.match(finalReadback.run, /git rev-parse HEAD/);
  assert.match(finalReadback.run, /git status --porcelain --untracked-files=normal/);
  assert.doesNotMatch(JSON.stringify(job), /\bsecrets\.|packages:\s*write|id-token:\s*write/i);

  assert.match(deploymentSmokeContents, /docker_test_begin deployment-smoke/);
  assert.match(deploymentSmokeContents, /docker_storage_preflight/);
  assert.match(deploymentSmokeContents, /docker_buildx_preflight/);
  assert.match(deploymentSmokeContents, /build_image_set linux\/amd64/);
  assert.match(deploymentSmokeContents, /trap cleanup EXIT INT TERM/);
  assert.match(deploymentSmokeContents, /docker_test_finish/);
  assert.match(deploymentSmokeContents, /no residual owned resources/);
});

test('GHCR publication is manual, exact-source, immutable, and digest-addressed', async () => {
  assert.deepEqual(Object.keys(publicationWorkflow.on), ['workflow_dispatch']);
  assert.deepEqual(publicationWorkflow.permissions, {
    contents: 'read',
    packages: 'write',
    attestations: 'write',
    'id-token': 'write',
  });
  assert.deepEqual(publicationWorkflow.on.workflow_dispatch.inputs.source_sha, {
    description: 'Full source commit SHA; WORKING requires current main',
    required: true,
    type: 'string',
  });

  assert.equal(
    publicationWorkflow.jobs.publish.strategy.matrix,
    '${{ fromJSON(needs.validate-source.outputs.matrix) }}',
  );

  const steps = publicationWorkflow.jobs.publish.steps;
  const build = publicationWorkflow.jobs.build.steps.find(
    (step) => step.name === 'Build exact linux/amd64 image locally when absent',
  );
  const attest = steps.find((step) => step.name === 'Attest exact image provenance');
  const upload = steps.find((step) => step.name === 'Upload digest mapping');
  assert.equal(build.if, "steps.inventory.outputs.state == 'absent'");
  assert.equal(build.with.platforms, 'linux/amd64');
  assert.equal(build.with.target, 'runtime');
  assert.equal(build.with.load, true);
  assert.equal(build.with.push, false);
  assert.equal(build.with.provenance, false);
  assert.equal(
    build.with.tags,
    '${{ matrix.package }}:sha-${{ needs.validate-source.outputs.source_sha }}',
  );
  assert.match(
    build.with.labels,
    /org\.opencontainers\.image\.source=https:\/\/github\.com\/\$\{\{ github\.repository \}\}/,
  );
  assert.match(
    build.with.labels,
    /org\.opencontainers\.image\.revision=\$\{\{ needs\.validate-source\.outputs\.source_sha \}\}/,
  );
  assert.equal(attest.with['subject-name'], '${{ steps.image.outputs.package }}');
  assert.equal(attest.with['subject-digest'], '${{ steps.image.outputs.digest }}');
  assert.equal(attest.with['push-to-registry'], true);
  assert.equal(upload.with['if-no-files-found'], 'error');

  assert.match(publicationWorkflowContents, /refs\/heads\/main/);
  assert.match(publicationWorkflowContents, /const sha = \//);
  assert.match(publicationWorkflowContents, /WORKFLOW_REF.*github\.ref/);
  assert.match(publicationWorkflowContents, /WORKFLOW_SHA.*github\.sha/);
  assert.match(publicationWorkflowContents, /source or publication scope rejected/);
  assert.match(
    publicationWorkflowContents,
    /registry digest readback does not match the pushed manifest/,
  );
  assert.match(
    publicationWorkflowContents,
    /deploymentRef: `\$\{process\.env\.PACKAGE\}@\$\{process\.env\.DIGEST\}`/,
  );
  assert.doesNotMatch(
    publicationWorkflowContents,
    /the exact source tag already exists; refusing overwrite/,
  );
  assert.doesNotMatch(publicationWorkflowContents, /\b(?:push|pull_request|schedule):\s*(?:\n|$)/m);
  assert.doesNotMatch(publicationWorkflowContents, /(?:^|[^-])\blatest\b/i);
  assert.doesNotMatch(publicationWorkflowContents, /\bsecrets\.|\bPAT\b|personal access token/i);
  assert.doesNotMatch(publicationWorkflowContents, /visibility|package.*public/i);
});

test('GHCR publication inventories all tags before resumable non-overwriting jobs', () => {
  assert.deepEqual(publicationWorkflow.jobs.publish.needs, [
    'validate-source',
    'inventory',
    'build',
  ]);
  assert.equal(publicationWorkflow.jobs.inventory.needs, 'validate-source');
  assert.equal(publicationWorkflow.jobs.publish.strategy['fail-fast'], false);

  const inventoryStep = publicationWorkflow.jobs.inventory.steps.find((step) =>
    step.name.startsWith('Classify all six'),
  );
  const imageStep = publicationWorkflow.jobs.publish.steps.find((step) =>
    step.name.startsWith('Adopt verified digest'),
  );
  assert.ok(inventoryStep);
  assert.ok(imageStep);
  for (const image of publicationImages) {
    assert.match(inventoryStep.run, new RegExp(`${image.service}=${image.package}`));
  }
  assert.match(inventoryStep.run, /org\.opencontainers\.image\.source/);
  assert.match(inventoryStep.run, /org\.opencontainers\.image\.revision/);
  assert.match(inventoryStep.run, /image\.os !== 'linux'/);
  assert.match(inventoryStep.run, /image\.architecture !== 'amd64'/);
  assert.match(inventoryStep.run, /ambiguous inventory state/);
  assert.match(imageStep.run, /INVENTORY_STATE" = 'existing'/);
  assert.match(imageStep.run, /publication_state='adopted'/);
  assert.match(imageStep.run, /INVENTORY_STATE" = 'absent'/);
  assert.match(imageStep.run, /tag appeared after the complete inventory; refusing overwrite/);
  assert.equal((imageStep.run.match(/docker push/g) ?? []).length, 1);
});

test('inventory validator accepts first-run, partial, and complete retry states but rejects conflict', async (t) => {
  const inventoryStep = publicationWorkflow.jobs.inventory.steps.find((step) =>
    step.name.startsWith('Classify all six'),
  );
  const script = extractValidator(inventoryStep.run, 'INVENTORY');

  for (const scenario of [
    { name: 'first run', states: publicationImages.map(() => 'absent') },
    {
      name: 'partial after push',
      states: publicationImages.map((_, index) => (index < 2 ? 'existing' : 'absent')),
    },
    { name: 'retry with all existing valid', states: publicationImages.map(() => 'existing') },
  ]) {
    await t.test(scenario.name, () => {
      const directory = mkdtempSync(path.join(tmpdir(), 'kovcheg-ghcr-inventory-'));
      try {
        writeJsonRecords(
          path.join(directory, 'publication-inventory'),
          publicationImages.map((image, index) =>
            inventoryRecord(image, index, scenario.states[index]),
          ),
        );
        const result = runValidator({ directory, script });
        assert.equal(result.status, 0, result.stderr);
        const output = JSON.parse(
          readFileSync(path.join(directory, 'publication-inventory/inventory.json'), 'utf8'),
        );
        assert.equal(output.images.length, 6);
      } finally {
        rmSync(directory, { force: true, recursive: true });
      }
    });
  }

  await t.test('conflicting existing tag', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'kovcheg-ghcr-inventory-'));
    try {
      const records = publicationImages.map((image, index) =>
        inventoryRecord(image, index, 'existing'),
      );
      records[0].sourceSha = 'b'.repeat(40);
      writeJsonRecords(path.join(directory, 'publication-inventory'), records);
      const result = runValidator({ directory, script });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /source, tag, or platform mismatch/);
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });
});

test('aggregate gate requires six unique mappings with attestations', async (t) => {
  const aggregateStep = publicationWorkflow.jobs.aggregate.steps.find((step) =>
    step.name.startsWith('Validate and write aggregate'),
  );
  const downloadStep = publicationWorkflow.jobs.aggregate.steps.find((step) =>
    step.name.startsWith('Download exactly the fixed'),
  );
  const uploadStep = publicationWorkflow.jobs.aggregate.steps.find((step) =>
    step.name.startsWith('Upload aggregate'),
  );
  const script = extractValidator(aggregateStep.run, 'AGGREGATE');
  assert.deepEqual(publicationWorkflow.jobs.aggregate.needs, ['validate-source', 'publish']);
  assert.equal(
    downloadStep.with.pattern,
    'ghcr-digest-*-${{ needs.validate-source.outputs.source_sha }}',
  );
  assert.equal(downloadStep.with['merge-multiple'], true);
  assert.equal(uploadStep.with['if-no-files-found'], 'error');

  await t.test('complete aggregate succeeds', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'kovcheg-ghcr-aggregate-'));
    try {
      writeJsonRecords(
        path.join(directory, 'publication-mappings'),
        publicationImages.map(mappingRecord),
      );
      const result = runValidator({ directory, script });
      assert.equal(result.status, 0, result.stderr);
      const output = JSON.parse(
        readFileSync(path.join(directory, 'ghcr-six-image-mapping.json'), 'utf8'),
      );
      assert.equal(output.imageCount, 6);
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });

  for (const scenario of [
    {
      name: 'missing mapping',
      records: publicationImages.slice(0, 5).map(mappingRecord),
      error: /exactly 6 mapping artifacts/,
    },
    {
      name: 'missing attestation',
      records: publicationImages.map((image, index) => {
        const record = mappingRecord(image, index);
        if (index === 0) record.attestation.id = '';
        return record;
      }),
      error: /incomplete or conflicting publication evidence/,
    },
    {
      name: 'duplicate mapping',
      records: publicationImages.map((image, index) =>
        mappingRecord(index === 5 ? publicationImages[0] : image, index),
      ),
      error: /duplicate service or package/,
    },
  ]) {
    await t.test(scenario.name, () => {
      const directory = mkdtempSync(path.join(tmpdir(), 'kovcheg-ghcr-aggregate-'));
      try {
        writeJsonRecords(path.join(directory, 'publication-mappings'), scenario.records);
        const result = runValidator({ directory, script });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, scenario.error);
      } finally {
        rmSync(directory, { force: true, recursive: true });
      }
    });
  }
});

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

function runValidator({ directory, script }) {
  return spawnSync(process.execPath, ['--input-type=module'], {
    cwd: directory,
    encoding: 'utf8',
    env: { ...process.env, SOURCE_SHA: sourceSha },
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

function mappingRecord(image, index) {
  const digest = `sha256:${(index + 1).toString(16).repeat(64)}`;
  return {
    service: image.service,
    package: image.package,
    digest,
    sourceSha,
    navigationTag: `sha-${sourceSha}`,
    platform: 'linux/amd64',
    deploymentRef: `${image.package}@${digest}`,
    publicationState: index % 2 === 0 ? 'published' : 'adopted',
    attestation: {
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
    description: 'Full commit SHA that must equal the current main head',
    required: true,
    type: 'string',
  });

  const images = publicationWorkflow.jobs.publish.strategy.matrix.include;
  assert.deepEqual(images, publicationImages);

  const steps = publicationWorkflow.jobs.publish.steps;
  const build = steps.find(
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

  assert.match(publicationWorkflowContents, /git ls-remote .*refs\/heads\/main/);
  assert.match(
    publicationWorkflowContents,
    /source_sha must contain exactly 40 hexadecimal characters/,
  );
  assert.match(publicationWorkflowContents, /WORKFLOW_REF.*github\.ref/);
  assert.match(publicationWorkflowContents, /WORKFLOW_SHA.*github\.sha/);
  assert.match(
    publicationWorkflowContents,
    /the workflow must run from the exact current main commit/,
  );
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
  assert.deepEqual(publicationWorkflow.jobs.publish.needs, ['validate-source', 'inventory']);
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
    step.name.startsWith('Download exactly six'),
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

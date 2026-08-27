import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { parse } from 'yaml';

import { repositoryRoot } from './lib.mjs';
import { analyzeWorkflow } from './workflow-policy-core.mjs';

const fixtureDirectory = path.join(repositoryRoot, 'verification/fixtures/workflow-policy');

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

test('GHCR publication is manual, exact-source, immutable, and digest-addressed', async () => {
  const workflowPath = path.join(repositoryRoot, '.github/workflows/publish-ghcr-images.yml');
  const contents = await readFile(workflowPath, 'utf8');
  const workflow = parse(contents);

  assert.deepEqual(Object.keys(workflow.on), ['workflow_dispatch']);
  assert.deepEqual(workflow.permissions, {
    contents: 'read',
    packages: 'write',
    attestations: 'write',
    'id-token': 'write',
  });
  assert.deepEqual(workflow.on.workflow_dispatch.inputs.source_sha, {
    description: 'Full commit SHA that must equal the current main head',
    required: true,
    type: 'string',
  });

  const images = workflow.jobs.publish.strategy.matrix.include;
  assert.deepEqual(images, [
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
  ]);

  const steps = workflow.jobs.publish.steps;
  const build = steps.find((step) => step.name === 'Build exact linux/amd64 image locally');
  const attest = steps.find((step) => step.name === 'Attest exact image provenance');
  const upload = steps.find((step) => step.name === 'Upload digest mapping');
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
  assert.equal(attest.with['subject-name'], '${{ steps.publish.outputs.package }}');
  assert.equal(attest.with['subject-digest'], '${{ steps.publish.outputs.digest }}');
  assert.equal(attest.with['push-to-registry'], true);
  assert.equal(upload.with['if-no-files-found'], 'error');

  assert.match(contents, /git ls-remote .*refs\/heads\/main/);
  assert.match(contents, /source_sha must contain exactly 40 hexadecimal characters/);
  assert.match(contents, /WORKFLOW_REF.*github\.ref/);
  assert.match(contents, /WORKFLOW_SHA.*github\.sha/);
  assert.match(contents, /the workflow must run from the exact current main commit/);
  assert.match(contents, /the exact source tag already exists; refusing overwrite/);
  assert.match(contents, /registry digest readback does not match the pushed manifest/);
  assert.match(contents, /deploymentRef: `\$\{process\.env\.PACKAGE\}@\$\{process\.env\.DIGEST\}`/);
  assert.doesNotMatch(contents, /\b(?:push|pull_request|schedule):\s*(?:\n|$)/m);
  assert.doesNotMatch(contents, /(?:^|[^-])\blatest\b/i);
  assert.doesNotMatch(contents, /\bsecrets\.|\bPAT\b|personal access token/i);
  assert.doesNotMatch(contents, /visibility|package.*public/i);
});

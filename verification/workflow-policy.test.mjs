import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

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

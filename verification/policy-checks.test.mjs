import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { repositoryRoot } from './lib.mjs';
import { scanPolicyFile } from './policy-checks-core.mjs';

const fixtureDirectory = path.join(repositoryRoot, 'verification/fixtures/policy-checks');

test('detects every supported focused and skipped Vitest form', async () => {
  const contents = await readFile(path.join(fixtureDirectory, 'supported.fixture'), 'utf8');
  const findings = scanPolicyFile('supported.ts', contents);
  assert.deepEqual(
    findings.map((finding) => finding.detail),
    [
      'describe.only',
      'it.skip',
      'test.skipIf',
      'test.todo',
      'test.skip',
      'test.{skip}',
      'it.{todo}',
      'describe.{only}',
      'context.skip',
    ],
  );
});

test('does not flag comments, strings, ordinary tests, or false object flags', async () => {
  const contents = await readFile(path.join(fixtureDirectory, 'clean.fixture'), 'utf8');
  assert.deepEqual(scanPolicyFile('clean.ts', contents), []);
});

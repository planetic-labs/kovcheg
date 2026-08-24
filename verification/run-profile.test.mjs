import assert from 'node:assert/strict';
import test from 'node:test';

import {
  aggregateStatuses,
  classifySpawnResult,
  countStatuses,
  evaluateToolchain,
  preserveNestedSummary,
} from './profile-status.mjs';

test('exit code 2 and a missing executable remain TOOL_UNAVAILABLE', () => {
  assert.equal(classifySpawnResult({ status: 2 }), 'TOOL_UNAVAILABLE');
  assert.equal(
    classifySpawnResult({ error: Object.assign(new Error('missing'), { code: 'ENOENT' }) }),
    'TOOL_UNAVAILABLE',
  );
});

test('missing corepack cannot throw while the toolchain status is recorded', () => {
  const result = evaluateToolchain({
    corepackResult: { error: Object.assign(new Error('missing'), { code: 'ENOENT' }) },
    expectedNode: '24.19.0',
    expectedPnpm: '11.22.0',
    nodeVersion: '24.19.0',
  });
  assert.deepEqual(result.actual, { node: '24.19.0', pnpm: null });
  assert.equal(result.status, 'TOOL_UNAVAILABLE');
});

test('nested summaries preserve every verification status', () => {
  const statuses = ['PASS', 'FAIL', 'INFORMATIONAL', 'TOOL_UNAVAILABLE', 'NOT_APPLICABLE'];
  const nestedSummary = preserveNestedSummary({
    profile: 'fixture',
    status: 'TOOL_UNAVAILABLE',
    steps: statuses.map((status) => ({ name: status.toLowerCase(), status })),
  });
  const parentSteps = [{ name: 'nested', status: nestedSummary.status, nestedSummary }];

  assert.deepEqual(
    nestedSummary.steps.map((step) => step.status),
    statuses,
  );
  assert.deepEqual(countStatuses(parentSteps), {
    PASS: 1,
    FAIL: 1,
    INFORMATIONAL: 1,
    TOOL_UNAVAILABLE: 2,
    NOT_APPLICABLE: 1,
  });
  assert.equal(aggregateStatuses(statuses), 'FAIL');
});

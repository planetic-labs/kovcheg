import assert from 'node:assert/strict';
import test from 'node:test';

import {
  aggregateStatuses,
  classifySpawnResult,
  countStatuses,
  evaluateToolchain,
  preserveNestedSummary,
  resolveNestedSummary,
} from './profile-status.mjs';

const expectedGit = {
  head: '1111111111111111111111111111111111111111',
  tree: '2222222222222222222222222222222222222222',
};
const expectedInvocationId = 'current-child-invocation';
const stepStartedAt = Date.parse('2026-08-24T08:00:00.000Z');

function nestedSummary(overrides = {}) {
  return {
    generatedAt: '2026-08-24T08:00:00.001Z',
    git: expectedGit,
    invocationId: expectedInvocationId,
    profile: 'fast',
    status: 'PASS',
    steps: [{ name: 'fixture', status: 'PASS' }],
    ...overrides,
  };
}

function resolve({ childResult, childStatus, summary }) {
  return resolveNestedSummary({
    artifactPrepared: true,
    childResult,
    childStatus,
    expectedGit,
    expectedInvocationId,
    stepStartedAt,
    summary,
  });
}

test('generic exit code 2 is FAIL', () => {
  assert.equal(classifySpawnResult({ status: 2 }), 'FAIL');
});

test('exit code 2 requires explicit TOOL_UNAVAILABLE opt-in', () => {
  assert.equal(
    classifySpawnResult({ status: 2 }, { unavailableExitCodes: [2] }),
    'TOOL_UNAVAILABLE',
  );
});

test('a missing executable is TOOL_UNAVAILABLE', () => {
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

test('stale PASS cannot replace a current child FAIL', () => {
  const resolution = resolve({
    childResult: { status: 1 },
    childStatus: 'FAIL',
    summary: nestedSummary({ generatedAt: '2026-08-24T07:59:59.999Z' }),
  });
  assert.equal(resolution.status, 'FAIL');
  assert.match(resolution.nestedSummaryError, /predates/);
});

test('stale PASS cannot replace a current child TOOL_UNAVAILABLE', () => {
  const childResult = { status: 2 };
  const resolution = resolve({
    childResult,
    childStatus: classifySpawnResult(childResult, { unavailableExitCodes: [2] }),
    summary: nestedSummary({ generatedAt: '2026-08-24T07:59:59.999Z' }),
  });
  assert.equal(resolution.status, 'TOOL_UNAVAILABLE');
  assert.match(resolution.nestedSummaryError, /predates/);
});

test('mismatched HEAD or tree cannot produce PASS', () => {
  for (const git of [
    { ...expectedGit, head: '3333333333333333333333333333333333333333' },
    { ...expectedGit, tree: '4444444444444444444444444444444444444444' },
  ]) {
    const resolution = resolve({
      childResult: { status: 0 },
      childStatus: 'PASS',
      summary: nestedSummary({ git }),
    });
    assert.equal(resolution.status, 'FAIL');
    assert.match(resolution.nestedSummaryError, /HEAD\/tree/);
  }
});

test('a summary from another child invocation cannot produce PASS', () => {
  const resolution = resolve({
    childResult: { status: 0 },
    childStatus: 'PASS',
    summary: nestedSummary({ invocationId: 'different-child-invocation' }),
  });
  assert.equal(resolution.status, 'FAIL');
  assert.match(resolution.nestedSummaryError, /invocationId/);
});

test('a fresh PASS contradicting the current child FAIL cannot produce PASS', () => {
  const resolution = resolve({
    childResult: { status: 1 },
    childStatus: 'FAIL',
    summary: nestedSummary(),
  });
  assert.equal(resolution.status, 'FAIL');
  assert.match(resolution.nestedSummaryError, /contradicts/);
});

test('a fresh matching nested summary is accepted', () => {
  const resolution = resolve({
    childResult: { status: 0 },
    childStatus: 'PASS',
    summary: nestedSummary(),
  });
  assert.equal(resolution.status, 'PASS');
  assert.equal(resolution.nestedSummary.invocationId, expectedInvocationId);
});

test('a fresh nested profile can propagate TOOL_UNAVAILABLE', () => {
  const childResult = { status: 2 };
  const resolution = resolve({
    childResult,
    childStatus: classifySpawnResult(childResult, { unavailableExitCodes: [2] }),
    summary: nestedSummary({
      status: 'TOOL_UNAVAILABLE',
      steps: [{ name: 'tool', status: 'TOOL_UNAVAILABLE' }],
    }),
  });
  assert.equal(resolution.status, 'TOOL_UNAVAILABLE');
  assert.equal(resolution.nestedSummary.status, 'TOOL_UNAVAILABLE');
});

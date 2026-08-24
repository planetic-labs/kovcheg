export const VERIFICATION_STATUSES = [
  'PASS',
  'FAIL',
  'INFORMATIONAL',
  'TOOL_UNAVAILABLE',
  'NOT_APPLICABLE',
];

const statusSet = new Set(VERIFICATION_STATUSES);

export function classifySpawnResult(result, options = {}) {
  if (result.error?.code === 'ENOENT') return 'TOOL_UNAVAILABLE';
  if (result.status === 0) {
    if (statusSet.has(options.successStatus)) return options.successStatus;
    return options.informational ? 'INFORMATIONAL' : 'PASS';
  }
  if (options.unavailablePattern?.test(`${result.stdout ?? ''}\n${result.stderr ?? ''}`)) {
    return 'TOOL_UNAVAILABLE';
  }
  if (options.unavailableExitCodes?.includes(result.status)) return 'TOOL_UNAVAILABLE';
  return 'FAIL';
}

export function aggregateStatuses(statuses) {
  if (statuses.includes('FAIL')) return 'FAIL';
  if (statuses.includes('TOOL_UNAVAILABLE')) return 'TOOL_UNAVAILABLE';
  if (statuses.includes('PASS')) return 'PASS';
  if (statuses.includes('INFORMATIONAL')) return 'INFORMATIONAL';
  return 'NOT_APPLICABLE';
}

export function exitCodeForStatus(status) {
  if (status === 'FAIL') return 1;
  if (status === 'TOOL_UNAVAILABLE') return 2;
  return 0;
}

export function evaluateToolchain({ corepackResult, expectedNode, expectedPnpm, nodeVersion }) {
  const pnpmVersion = corepackResult.stdout?.trim() || null;
  let status = classifySpawnResult(corepackResult);
  if (status === 'PASS' && (nodeVersion !== expectedNode || pnpmVersion !== expectedPnpm)) {
    status = 'FAIL';
  }
  return {
    actual: { node: nodeVersion, pnpm: pnpmVersion },
    expected: { node: expectedNode, pnpm: expectedPnpm },
    status,
  };
}

export function preserveNestedSummary(summary) {
  if (!statusSet.has(summary.status) || !Array.isArray(summary.steps)) {
    throw new Error('Nested verification summary has an invalid status contract.');
  }
  return {
    durationMs: summary.durationMs,
    generatedAt: summary.generatedAt,
    git: summary.git,
    invocationId: summary.invocationId,
    profile: summary.profile,
    status: summary.status,
    statusCounts: summary.statusCounts,
    steps: summary.steps,
    tools: summary.tools,
  };
}

export function resolveNestedSummary({
  artifactPrepared,
  childResult,
  childStatus,
  expectedGit,
  expectedInvocationId,
  stepStartedAt,
  summary,
  summaryReadError,
}) {
  try {
    if (!artifactPrepared) {
      throw new Error('Nested summary artifact could not be cleared before the child invocation.');
    }
    if (summaryReadError) throw summaryReadError;
    const nestedSummary = preserveNestedSummary(summary);
    if (nestedSummary.invocationId !== expectedInvocationId) {
      throw new Error('Nested summary invocationId does not match the current child invocation.');
    }

    const generatedAt = Date.parse(nestedSummary.generatedAt);
    if (!Number.isFinite(generatedAt) || generatedAt < stepStartedAt) {
      throw new Error('Nested summary generatedAt predates the current child invocation.');
    }
    if (
      nestedSummary.git?.head !== expectedGit?.head ||
      nestedSummary.git?.tree !== expectedGit?.tree
    ) {
      throw new Error('Nested summary HEAD/tree does not match the current invocation.');
    }
    if (childResult.error || childResult.status !== exitCodeForStatus(nestedSummary.status)) {
      throw new Error('Nested summary status contradicts the current child exit code.');
    }
    return { nestedSummary, status: nestedSummary.status };
  } catch (error) {
    return {
      nestedSummaryError: error.message,
      status: childStatus === 'PASS' ? 'FAIL' : childStatus,
    };
  }
}

export function countStatuses(steps) {
  const counts = Object.fromEntries(VERIFICATION_STATUSES.map((status) => [status, 0]));
  function count(step) {
    if (statusSet.has(step.status)) counts[step.status] += 1;
    for (const nestedStep of step.nestedSummary?.steps ?? []) count(nestedStep);
  }
  for (const step of steps) count(step);
  return counts;
}

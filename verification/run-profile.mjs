import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFileSync, rmSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';

import { artifactRoot, collectExecutionMetadata, repositoryRoot, writeJson } from './lib.mjs';
import {
  aggregateStatuses,
  classifySpawnResult,
  countStatuses,
  evaluateToolchain,
  exitCodeForStatus,
  resolveNestedSummary,
} from './profile-status.mjs';

const profile = process.argv[2];
if (!['code-quality', 'deep', 'fast'].includes(profile)) {
  console.error('Usage: node verification/run-profile.mjs <code-quality|fast|deep>');
  process.exit(2);
}

await mkdir(artifactRoot, { recursive: true });
const startedAt = Date.now();
const invocationId = process.env.VERIFICATION_INVOCATION_ID ?? randomUUID();
const invocationGit = (await collectExecutionMetadata()).git;
const steps = [];

function printOutput(result) {
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
}

function runStep(name, command, args, options = {}) {
  const stepStartedAt = Date.now();
  const nestedSummaryPath = options.nestedSummaryPath
    ? path.join(repositoryRoot, options.nestedSummaryPath)
    : null;
  const nestedInvocationId = nestedSummaryPath ? randomUUID() : null;
  let artifactPrepared = true;
  let artifactPreparationError;
  if (nestedSummaryPath) {
    try {
      rmSync(nestedSummaryPath, { force: true });
    } catch (error) {
      artifactPrepared = false;
      artifactPreparationError = error;
    }
  }
  console.log(`\n[${name}] ${command} ${args.join(' ')}`);
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      NO_COLOR: '1',
      ...(nestedInvocationId ? { VERIFICATION_INVOCATION_ID: nestedInvocationId } : {}),
    },
    maxBuffer: 100 * 1024 * 1024,
  });
  printOutput(result);

  let status = classifySpawnResult(result, options);

  const step = {
    command: [command, ...args].join(' '),
    durationMs: Date.now() - stepStartedAt,
    name,
    status,
  };
  if (nestedSummaryPath) {
    let summary;
    let summaryReadError = artifactPreparationError;
    try {
      summary = JSON.parse(readFileSync(nestedSummaryPath, 'utf8'));
    } catch (error) {
      summaryReadError ??= error;
    }
    const resolution = resolveNestedSummary({
      artifactPrepared,
      childResult: result,
      childStatus: status,
      expectedGit: invocationGit,
      expectedInvocationId: nestedInvocationId,
      stepStartedAt,
      summary,
      summaryReadError,
    });
    step.nestedInvocationId = nestedInvocationId;
    if (resolution.nestedSummary) step.nestedSummary = resolution.nestedSummary;
    if (resolution.nestedSummaryError) {
      step.nestedSummaryError = resolution.nestedSummaryError;
    }
    status = resolution.status;
    step.status = status;
  }
  steps.push(step);
  console.log(`[${name}] ${status} (${step.durationMs} ms)`);
  return status;
}

function runToolchainCheck() {
  const stepStartedAt = Date.now();
  const nodeVersion = process.version.replace(/^v/, '');
  const pnpm = spawnSync('corepack', ['pnpm', '--version'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
  });
  const expectedNode = '24.19.0';
  const expectedPnpm = '11.22.0';
  const evaluation = evaluateToolchain({
    corepackResult: pnpm,
    expectedNode,
    expectedPnpm,
    nodeVersion,
  });
  steps.push({
    actual: evaluation.actual,
    durationMs: Date.now() - stepStartedAt,
    expected: evaluation.expected,
    name: 'toolchain',
    status: evaluation.status,
  });
  console.log(
    `[toolchain] ${evaluation.status}: Node ${nodeVersion}, pnpm ${evaluation.actual.pnpm ?? 'unavailable'}`,
  );
}

function runDiffCheck() {
  const base = process.env.VERIFY_BASE_REF;
  const args = ['diff', '--check'];
  if (base) args.push(`${base}...HEAD`);
  runStep('git-diff-check', 'git', args);
  if (base) runStep('working-tree-diff-check', 'git', ['diff', '--check']);
}

function runCodeQualityChecks() {
  runStep('verification-regression-fixtures', 'node', [
    '--test',
    'verification/docker-test-lifecycle.test.mjs',
    'verification/source-analysis.test.mjs',
    'verification/html-inspection.test.mjs',
    'verification/policy-checks.test.mjs',
    'verification/run-profile.test.mjs',
    'verification/workflow-policy.test.mjs',
  ]);
  runStep('focused-tests-and-suppressions', 'node', ['verification/policy-checks.mjs']);
  runStep('knip-monorepo-regression', 'node', ['verification/knip-check.mjs', 'default'], {
    unavailableExitCodes: [2],
  });
  runStep('knip-production-regression', 'node', ['verification/knip-check.mjs', 'production'], {
    unavailableExitCodes: [2],
  });
  runStep('workspace-boundaries-and-cycles', 'node', ['verification/source-analysis.mjs']);
  runStep('production-entrypoints', 'node', ['verification/entrypoint-policy.mjs']);
  runStep('deployment-contract', 'node', ['infra/deployment/verify.mjs']);
  runStep('workflow-policy', 'node', ['verification/workflow-policy.mjs']);
}

if (profile === 'code-quality') {
  runToolchainCheck();
  runCodeQualityChecks();
  runDiffCheck();
} else if (profile === 'fast') {
  runToolchainCheck();
  runStep('prettier', 'corepack', ['pnpm', 'format:check']);
  runStep('eslint', 'corepack', ['pnpm', 'exec', 'eslint', '.', '--max-warnings=0']);
  runStep('strict-typescript', 'corepack', ['pnpm', 'typecheck']);
  runStep('test-suite', 'corepack', ['pnpm', 'test']);
  runCodeQualityChecks();
  runStep('dependency-audit', 'corepack', ['pnpm', 'audit', '--audit-level=high'], {
    unavailablePattern:
      /ERR_PNPM_META_FETCH_FAIL|EAI_AGAIN|ENETUNREACH|Could not resolve host|network request failed/i,
  });
  runDiffCheck();
} else {
  runStep('fast-profile', 'node', ['verification/run-profile.mjs', 'fast'], {
    nestedSummaryPath: '.artifacts/verification/fast-summary.json',
    unavailableExitCodes: [2],
  });
  runStep(
    'critical-branch-coverage',
    'corepack',
    [
      'pnpm',
      'exec',
      'vitest',
      'run',
      '--config',
      'verification/vitest.critical.config.ts',
      '--coverage',
    ],
    { informational: true },
  );
  runStep('normalize-coverage-report', 'node', ['verification/normalize-coverage.mjs']);
  runStep(
    'dependency-graph-and-complexity',
    'node',
    [
      'verification/source-analysis.mjs',
      '--output',
      '.artifacts/verification/deep/source-health.json',
    ],
    { informational: true },
  );
  runStep('duplication-report', 'corepack', ['pnpm', 'verify:duplication-report'], {
    informational: true,
  });
  runStep(
    'production-deploy-inventory',
    'node',
    [
      'verification/entrypoint-policy.mjs',
      '--output',
      '.artifacts/verification/deep/production-inventory.json',
    ],
    { informational: true },
  );
  runStep('web-production-build', 'corepack', ['pnpm', '--filter', '@kovcheg/web', 'build']);
  runStep('client-bundle-manifest', 'node', ['verification/bundle-manifest.mjs'], {
    informational: true,
  });
  runStep(
    'baseline-exceptions-and-deferred-profiles',
    'node',
    ['verification/report-metadata.mjs'],
    { informational: true },
  );
}

const overallStatus = aggregateStatuses(steps.map((step) => step.status));
const executionMetadata = await collectExecutionMetadata();
const summary = {
  ...executionMetadata,
  durationMs: Date.now() - startedAt,
  invocationId,
  profile,
  status: overallStatus,
  statusCounts: countStatuses(steps),
  steps,
};
await writeJson(path.join(artifactRoot, `${profile}-summary.json`), summary);
console.log(
  `\n${profile} profile: ${overallStatus} (${summary.durationMs} ms, ${steps.length} steps)`,
);
process.exit(exitCodeForStatus(overallStatus));

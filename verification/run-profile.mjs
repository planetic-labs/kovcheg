import { spawnSync } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';

import { artifactRoot, repositoryRoot, writeJson } from './lib.mjs';

const profile = process.argv[2];
if (!['code-quality', 'deep', 'fast'].includes(profile)) {
  console.error('Usage: node verification/run-profile.mjs <code-quality|fast|deep>');
  process.exit(2);
}

await mkdir(artifactRoot, { recursive: true });
const startedAt = Date.now();
const steps = [];

function printOutput(result) {
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
}

function runStep(name, command, args, options = {}) {
  const stepStartedAt = Date.now();
  console.log(`\n[${name}] ${command} ${args.join(' ')}`);
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    maxBuffer: 100 * 1024 * 1024,
  });
  printOutput(result);

  let status;
  if (result.error?.code === 'ENOENT') {
    status = 'TOOL_UNAVAILABLE';
  } else if (result.status === 0) {
    status = options.informational ? 'INFORMATIONAL' : 'PASS';
  } else if (options.unavailablePattern?.test(`${result.stdout ?? ''}\n${result.stderr ?? ''}`)) {
    status = 'TOOL_UNAVAILABLE';
  } else {
    status = 'FAIL';
  }

  const step = {
    command: [command, ...args].join(' '),
    durationMs: Date.now() - stepStartedAt,
    name,
    status,
  };
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
  let status = 'PASS';
  if (pnpm.error?.code === 'ENOENT') status = 'TOOL_UNAVAILABLE';
  else if (
    nodeVersion !== expectedNode ||
    pnpm.status !== 0 ||
    pnpm.stdout.trim() !== expectedPnpm
  ) {
    status = 'FAIL';
  }
  steps.push({
    actual: { node: nodeVersion, pnpm: pnpm.stdout?.trim() ?? null },
    durationMs: Date.now() - stepStartedAt,
    expected: { node: expectedNode, pnpm: expectedPnpm },
    name: 'toolchain',
    status,
  });
  console.log(`[toolchain] ${status}: Node ${nodeVersion}, pnpm ${pnpm.stdout.trim()}`);
}

function runDiffCheck() {
  const base = process.env.VERIFY_BASE_REF;
  const args = ['diff', '--check'];
  if (base) args.push(`${base}...HEAD`);
  runStep('git-diff-check', 'git', args);
  if (base) runStep('working-tree-diff-check', 'git', ['diff', '--check']);
}

function runCodeQualityChecks() {
  runStep('focused-tests-and-suppressions', 'node', ['verification/policy-checks.mjs']);
  runStep('knip-monorepo-regression', 'node', ['verification/knip-check.mjs', 'default']);
  runStep('knip-production-regression', 'node', ['verification/knip-check.mjs', 'production']);
  runStep('workspace-boundaries-and-cycles', 'node', ['verification/source-analysis.mjs']);
  runStep('production-entrypoints', 'node', ['verification/entrypoint-policy.mjs']);
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
  runStep('fast-profile', 'node', ['verification/run-profile.mjs', 'fast']);
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

const hasFailure = steps.some((step) => step.status === 'FAIL');
const hasUnavailable = steps.some((step) => step.status === 'TOOL_UNAVAILABLE');
const overallStatus = hasFailure ? 'FAIL' : hasUnavailable ? 'TOOL_UNAVAILABLE' : 'PASS';
const summary = {
  durationMs: Date.now() - startedAt,
  profile,
  status: overallStatus,
  steps,
};
await writeJson(path.join(artifactRoot, `${profile}-summary.json`), summary);
console.log(
  `\n${profile} profile: ${overallStatus} (${summary.durationMs} ms, ${steps.length} steps)`,
);
process.exit(overallStatus === 'PASS' ? 0 : overallStatus === 'TOOL_UNAVAILABLE' ? 2 : 1);

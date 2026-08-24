import { access, readFile } from 'node:fs/promises';
import path from 'node:path';

import { parse } from 'yaml';

import { readJson, repositoryRoot, writeJson } from './lib.mjs';

const manifest = await readJson('verification/entrypoints.json');
const baseline = await readJson('verification/baseline.json');
const findings = [];

async function requireFile(relativePath, kind) {
  try {
    await access(path.join(repositoryRoot, relativePath));
  } catch {
    findings.push({ kind, path: relativePath, reason: 'declared entrypoint is missing' });
  }
}

for (const application of manifest.productionApplications) {
  await requireFile(application.dockerfile, 'production-application');
  await requireFile(application.sourceEntrypoint, 'production-application');

  const dockerfile = await readFile(path.join(repositoryRoot, application.dockerfile), 'utf8');
  const targetPattern = new RegExp(`^FROM\\s+.+\\s+AS\\s+${application.target}$`, 'im');
  if (!targetPattern.test(dockerfile)) {
    findings.push({
      kind: 'production-application',
      path: application.dockerfile,
      reason: `missing Docker target ${application.target}`,
    });
  }
}

for (const shellEntrypoint of manifest.shellEntrypoints) {
  await requireFile(shellEntrypoint, 'shell-entrypoint');
}

for (const testEntrypoint of manifest.testOnlyEntrypoints) {
  await requireFile(testEntrypoint.path, 'test-only-entrypoint');
  if (testEntrypoint.reason.trim().length < 20) {
    findings.push({
      kind: 'test-only-entrypoint',
      path: testEntrypoint.path,
      reason: 'test-only classification lacks a reviewable explanation',
    });
  }
}

const compose = parse(await readFile(path.join(repositoryRoot, 'compose.yaml'), 'utf8'), {
  merge: true,
});
const composeDockerfiles = [
  ...new Set(
    Object.values(compose.services ?? {})
      .filter((service) => service.build !== undefined && service.profiles === undefined)
      .map((service) =>
        typeof service.build === 'string'
          ? 'Dockerfile'
          : (service.build.dockerfile ?? 'Dockerfile'),
      ),
  ),
].sort();
const declaredDockerfiles = manifest.productionApplications
  .map((application) => application.dockerfile)
  .sort();

if (JSON.stringify(composeDockerfiles) !== JSON.stringify(declaredDockerfiles)) {
  findings.push({
    actual: composeDockerfiles,
    expected: declaredDockerfiles,
    kind: 'compose-production-images',
    reason: 'production image inventory does not match Compose build services',
  });
}

const imageNames = manifest.productionApplications.map((application) => application.image).sort();
if (JSON.stringify(imageNames) !== JSON.stringify([...baseline.productionImages].sort())) {
  findings.push({
    actual: imageNames,
    expected: baseline.productionImages,
    kind: 'production-image-baseline',
    reason: 'production image inventory changed without a reviewed baseline update',
  });
}

const smoke = await readFile(path.join(repositoryRoot, 'infra/scripts/docker-smoke.sh'), 'utf8');
const requiredImageAssertions = [
  "-name '*.spec.js'",
  "-name '*.test.js'",
  "-name '*.integration-check.js'",
  'identity-stub',
  'test-api-main',
  'for package_manager in corepack npm npx pnpm pnpx yarn yarnpkg',
];
for (const assertion of requiredImageAssertions) {
  if (!smoke.includes(assertion)) {
    findings.push({
      kind: 'production-image-smoke-route',
      path: 'infra/scripts/docker-smoke.sh',
      reason: `missing runtime payload assertion: ${assertion}`,
    });
  }
}

const report = {
  actualImageProofCommand: 'pnpm docker:smoke',
  composeDockerfiles,
  findings,
  productionApplications: manifest.productionApplications,
  shellEntrypoints: manifest.shellEntrypoints,
  status: findings.length === 0 ? 'PASS' : 'FAIL',
  testOnlyEntrypoints: manifest.testOnlyEntrypoints,
};

const outputArgument = process.argv.indexOf('--output');
const output =
  outputArgument >= 0
    ? process.argv[outputArgument + 1]
    : '.artifacts/verification/production-entrypoints.json';
await writeJson(output, report);

if (findings.length > 0) {
  for (const finding of findings) {
    console.error(`${finding.kind}: ${finding.path ?? finding.reason}`);
  }
  process.exit(1);
}

console.log(
  `Production entrypoint policy passed for ${imageNames.length} unique application images.`,
);

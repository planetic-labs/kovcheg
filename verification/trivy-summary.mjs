import { access, readFile } from 'node:fs/promises';
import path from 'node:path';

import { collectExecutionMetadata, repositoryRoot, writeJson } from './lib.mjs';

const unavailableIndex = process.argv.indexOf('--tool-unavailable');
if (unavailableIndex >= 0) {
  const missingTools = process.argv.slice(unavailableIndex + 1);
  await writeJson('.artifacts/security/summary.json', {
    ...(await collectExecutionMetadata()),
    missingTools,
    status: 'TOOL_UNAVAILABLE',
  });
  process.exit(0);
}

const reportDirectory = path.join(repositoryRoot, '.artifacts', 'security');
const severities = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function emptyCounts() {
  return Object.fromEntries(severities.map((severity) => [severity, 0]));
}

async function readReport(file) {
  const reportPath = path.join(reportDirectory, file);
  try {
    await access(reportPath);
    return JSON.parse(await readFile(reportPath, 'utf8'));
  } catch {
    return null;
  }
}

function countFindings(report) {
  const vulnerabilities = emptyCounts();
  const misconfigurations = emptyCounts();
  for (const result of report?.Results ?? []) {
    for (const vulnerability of result.Vulnerabilities ?? []) {
      const severity = severities.includes(vulnerability.Severity)
        ? vulnerability.Severity
        : 'UNKNOWN';
      vulnerabilities[severity] += 1;
    }
    for (const misconfiguration of result.Misconfigurations ?? []) {
      const severity = severities.includes(misconfiguration.Severity)
        ? misconfiguration.Severity
        : 'UNKNOWN';
      misconfigurations[severity] += 1;
    }
  }
  return { misconfigurations, vulnerabilities };
}

const expectedReports = ['filesystem.json'];
const images = [];
for (const application of ['api', 'auth', 'edge', 'postgres', 'web', 'worker']) {
  const vulnerabilityFile = `${application}-image.json`;
  const blockingFile = `${application}-fixed-high-critical.json`;
  const sbomFile = `${application}-sbom.cdx.json`;
  expectedReports.push(vulnerabilityFile, blockingFile, sbomFile);
  images.push({
    application,
    fixedHighCritical: countFindings(await readReport(blockingFile)).vulnerabilities,
    vulnerabilities: countFindings(await readReport(vulnerabilityFile)).vulnerabilities,
  });
}

const missingReports = [];
for (const file of expectedReports) {
  if ((await readReport(file)) === null) missingReports.push(file);
}

const scanStatus = Number(process.env.TRIVY_SCAN_STATUS ?? 1);
const blockingStatus = Number(process.env.TRIVY_BLOCKING_STATUS ?? 1);
const report = {
  ...(await collectExecutionMetadata()),
  blockingPolicy: 'fixed HIGH and CRITICAL vulnerabilities in production images',
  filesystem: countFindings(await readReport('filesystem.json')),
  images,
  informationalPolicy: 'UNKNOWN, LOW, MEDIUM, filesystem vulnerabilities, and misconfigurations',
  missingReports,
  status: scanStatus === 0 && blockingStatus === 0 && missingReports.length === 0 ? 'PASS' : 'FAIL',
};

await writeJson('.artifacts/security/summary.json', report);
console.log(
  `Container security summary: ${report.status}; ${missingReports.length} missing reports.`,
);

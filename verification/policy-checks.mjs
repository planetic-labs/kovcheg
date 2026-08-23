import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { repositoryRoot, writeJson } from './lib.mjs';

const tracked = spawnSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {
  cwd: repositoryRoot,
  encoding: 'utf8',
});

if (tracked.status !== 0) {
  process.stderr.write(tracked.stderr);
  process.exit(1);
}

const extensions = new Set([
  '.cjs',
  '.js',
  '.json',
  '.jsonc',
  '.mjs',
  '.sh',
  '.ts',
  '.tsx',
  '.yaml',
  '.yml',
]);

const files = [...new Set(tracked.stdout.split('\0').filter(Boolean))]
  .filter((file) => extensions.has(path.extname(file)))
  .sort();
const findings = [];

const focusedOrSkippedTests = [
  /\b(?:describe|it|test)\s*\.\s*(?:only|skip)\s*\(/,
  /\b(?:xdescribe|xit|xtest)\s*\(/,
];

const suppressionRules = [
  {
    id: 'eslint-suppression',
    marker: /eslint-(?:disable|disable-next-line|disable-line)\b/,
    justified: (line) =>
      /eslint-(?:disable|disable-next-line|disable-line).*--\s*\S.{11,}/.test(line),
  },
  {
    id: 'typescript-suppression',
    marker: /@ts-(?:expect-error|ignore|nocheck)\b/,
    justified: (line) => /@ts-(?:expect-error|ignore|nocheck)\s*:\s*\S.{11,}/.test(line),
  },
  {
    id: 'coverage-suppression',
    marker: /(?:istanbul|c8)\s+ignore\b/,
    justified: (line) => /(?:istanbul|c8)\s+ignore.*--\s*\S.{11,}/.test(line),
  },
  {
    id: 'analysis-suppression',
    marker: /(?:knip-ignore|jscpd:ignore)/, // knip-ignore -- This line defines the scanner rule and does not suppress analysis.
    justified: (line) => /(?:knip-ignore|jscpd:ignore).*--\s*\S.{11,}/.test(line),
  },
];

for (const file of files) {
  const contents = await readFile(path.join(repositoryRoot, file), 'utf8');
  const lines = contents.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    if (focusedOrSkippedTests.some((pattern) => pattern.test(line))) {
      findings.push({
        file,
        line: index + 1,
        rule: 'focused-or-skipped-test',
      });
    }
    for (const rule of suppressionRules) {
      if (rule.marker.test(line) && !rule.justified(line)) {
        findings.push({ file, line: index + 1, rule: rule.id });
      }
    }
  }
}

const report = {
  filesScanned: files.length,
  findings,
  status: findings.length === 0 ? 'PASS' : 'FAIL',
};

await writeJson('.artifacts/verification/policy-checks.json', report);

if (findings.length > 0) {
  for (const finding of findings) {
    console.error(`${finding.file}:${finding.line} ${finding.rule}`);
  }
  process.exit(1);
}

console.log(`Policy scan passed for ${files.length} tracked or outgoing files.`);

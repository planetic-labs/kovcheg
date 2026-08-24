import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { repositoryRoot, writeJson } from './lib.mjs';
import { scanPolicyFile } from './policy-checks-core.mjs';

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

for (const file of files) {
  const contents = await readFile(path.join(repositoryRoot, file), 'utf8');
  findings.push(...scanPolicyFile(file, contents));
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

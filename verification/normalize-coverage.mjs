import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { repositoryRoot, writeJson } from './lib.mjs';

const reportPath = '.artifacts/verification/deep/coverage/coverage-summary.json';
const raw = JSON.parse(await readFile(path.join(repositoryRoot, reportPath), 'utf8'));
const files = [];

for (const [absolutePath, metrics] of Object.entries(raw)) {
  if (absolutePath === 'total') continue;
  const relativePath = path.relative(repositoryRoot, absolutePath).split(path.sep).join('/');
  if (relativePath.startsWith('../') || path.isAbsolute(relativePath)) {
    throw new Error(`Coverage path is outside the repository: ${absolutePath}`);
  }
  files.push({ metrics, path: relativePath });
}

files.sort((left, right) => left.path.localeCompare(right.path));
await writeJson(reportPath, {
  files,
  status: 'INFORMATIONAL',
  total: raw.total,
});
console.log(`Normalized coverage paths for ${files.length} repository files.`);

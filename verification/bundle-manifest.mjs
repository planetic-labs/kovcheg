import { access } from 'node:fs/promises';

import { fileMetadata, walkFiles, writeJson } from './lib.mjs';

const roots = ['apps/web/.next/static'];
const files = [];

for (const root of roots) {
  try {
    await access(root);
    files.push(...(await walkFiles(root)));
  } catch {
    // Some Next.js output directories are route-dependent and may not exist.
  }
}

const metadata = await Promise.all([...new Set(files)].sort().map(fileMetadata));
const report = {
  files: metadata,
  status: 'INFORMATIONAL',
  totalBytes: metadata.reduce((sum, item) => sum + item.bytes, 0),
};
await writeJson('.artifacts/verification/deep/client-bundle-manifest.json', report);
console.log(
  `Recorded ${metadata.length} client bundle files (${report.totalBytes} bytes) without an absolute budget.`,
);

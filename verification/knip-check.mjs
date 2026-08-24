import { spawnSync } from 'node:child_process';

import { readJson, repositoryRoot, writeJson } from './lib.mjs';

const mode = process.argv[2];
if (!['default', 'production'].includes(mode)) {
  console.error('Usage: node verification/knip-check.mjs <default|production>');
  process.exit(2);
}

const args = ['pnpm', 'exec', 'knip'];
if (mode === 'production') args.push('--production', '--strict');
args.push('--reporter', 'json', '--no-exit-code', '--treat-config-hints-as-errors');
const result = spawnSync('corepack', args, {
  cwd: repositoryRoot,
  encoding: 'utf8',
  maxBuffer: 50 * 1024 * 1024,
});

if (result.error?.code === 'ENOENT') {
  console.error('Knip toolchain is unavailable.');
  process.exit(2);
}
if (result.status !== 0) {
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exit(1);
}

let payload;
try {
  payload = JSON.parse(result.stdout);
} catch {
  process.stdout.write(result.stdout);
  console.error('Knip did not produce a valid JSON report.');
  process.exit(1);
}

function fingerprintItem(category, file, item) {
  if (Array.isArray(item)) {
    return `${category}:${file}:${item
      .map((entry) => entry.name)
      .sort()
      .join('|')}`;
  }
  const identity = item.name ?? item.symbol ?? item.specifier ?? JSON.stringify(item);
  return `${category}:${file}:${identity}`;
}

const current = [];
for (const issue of payload.issues ?? []) {
  for (const [category, items] of Object.entries(issue)) {
    if (category === 'file' || !Array.isArray(items)) continue;
    for (const item of items) {
      current.push(fingerprintItem(category, issue.file, item));
    }
  }
}
current.sort();

const baseline = await readJson('verification/knip-baseline.json');
const expected = [...baseline.modes[mode]].sort();
const expectedSet = new Set(expected);
const currentSet = new Set(current);
const added = current.filter((fingerprint) => !expectedSet.has(fingerprint));
const resolved = expected.filter((fingerprint) => !currentSet.has(fingerprint));
const report = {
  added,
  baseline: expected,
  current,
  mode,
  resolved,
  sourceCommit: baseline.sourceCommit,
  status: added.length === 0 ? 'PASS' : 'FAIL',
};
await writeJson(`.artifacts/verification/knip-${mode}.json`, report);

if (added.length > 0) {
  for (const fingerprint of added) console.error(`new Knip issue: ${fingerprint}`);
  process.exit(1);
}

console.log(
  `Knip ${mode} baseline passed: ${current.length} current, ${resolved.length} resolved, 0 new.`,
);

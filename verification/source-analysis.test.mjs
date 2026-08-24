import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { repositoryRoot } from './lib.mjs';
import { analyzeModuleGraph } from './source-analysis-core.mjs';

const fixtureDirectory = path.join(repositoryRoot, 'verification/fixtures/source-analysis');
const fixtureMap = new Map([
  ['apps/cycle/src/a.ts', 'cycle-a.fixture'],
  ['apps/cycle/src/b.ts', 'cycle-b.fixture'],
  ['apps/alpha/src/index.ts', 'boundary-alpha.fixture'],
  ['apps/beta/src/index.ts', 'boundary-beta.fixture'],
  ['packages/ext/src/main.mts', 'extension-main-mts.fixture'],
  ['packages/ext/src/dependency.mts', 'extension-dependency-mts.fixture'],
  ['packages/ext/src/main.cts', 'extension-main-cts.fixture'],
  ['packages/ext/src/dependency.cts', 'extension-dependency-cts.fixture'],
]);

async function loadFixtures() {
  return new Map(
    await Promise.all(
      [...fixtureMap].map(async ([sourceFile, fixture]) => [
        sourceFile,
        await readFile(path.join(fixtureDirectory, fixture), 'utf8'),
      ]),
    ),
  );
}

test('resolves emitted ESM specifiers and detects cycles and workspace violations', async () => {
  const sourceFiles = [...fixtureMap.keys()];
  const report = analyzeModuleGraph({
    allowedWorkspaceDependency: (source, target) => source === target,
    contentsByFile: await loadFixtures(),
    internalPackages: new Map(),
    sourceFiles,
    workspaceRoots: ['apps/alpha', 'apps/beta', 'apps/cycle', 'packages/ext'],
  });

  assert.deepEqual(report.cycles, ['apps/cycle/src/a.ts -> apps/cycle/src/b.ts']);
  assert.deepEqual(report.boundaryViolations, [
    {
      file: 'apps/alpha/src/index.ts',
      reason: 'apps/alpha cannot depend on apps/beta',
      target: 'apps/beta/src/index.ts',
    },
  ]);
  assert.deepEqual([...report.graph.get('apps/cycle/src/a.ts')], ['apps/cycle/src/b.ts']);
  assert.deepEqual(
    [...report.graph.get('packages/ext/src/main.mts')],
    ['packages/ext/src/dependency.mts'],
  );
  assert.deepEqual(
    [...report.graph.get('packages/ext/src/main.cts')],
    ['packages/ext/src/dependency.cts'],
  );
  assert.deepEqual(report.parseFailures, []);
});

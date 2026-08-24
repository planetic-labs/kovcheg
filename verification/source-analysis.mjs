import { readFile } from 'node:fs/promises';
import path from 'node:path';

import ts from 'typescript';

import { readJson, repositoryRoot, walkFiles, writeJson } from './lib.mjs';
import { analyzeModuleGraph } from './source-analysis-core.mjs';

const workspaceRoots = [
  'apps/api',
  'apps/auth',
  'apps/web',
  'apps/worker',
  'packages/config',
  'packages/contracts',
];
const internalPackages = new Map([
  ['@kovcheg/config', 'packages/config/src/index.ts'],
  ['@kovcheg/contracts', 'packages/contracts/src/index.ts'],
  ['@kovcheg/contracts/testing', 'packages/contracts/src/testing/index.ts'],
]);

const sourceFiles = (
  await Promise.all(
    ['apps', 'packages'].map((directory) =>
      walkFiles(directory, (file) => /\.(?:ts|tsx|mts|cts)$/.test(file)),
    ),
  )
)
  .flat()
  .filter(
    (file) =>
      file.includes('/src/') &&
      !/\.spec\.(?:ts|tsx|mts|cts)$/.test(file) &&
      !/\.integration-check\.(?:ts|tsx|mts|cts)$/.test(file) &&
      !file.includes('/src/testing/'),
  )
  .sort();
function allowedWorkspaceDependency(sourceWorkspace, targetWorkspace) {
  if (sourceWorkspace === targetWorkspace) return true;
  if (sourceWorkspace?.startsWith('apps/')) {
    return targetWorkspace === 'packages/config' || targetWorkspace === 'packages/contracts';
  }
  if (sourceWorkspace === 'packages/config') {
    return targetWorkspace === 'packages/contracts';
  }
  return false;
}

const contentsByFile = new Map(
  await Promise.all(
    sourceFiles.map(async (file) => [
      file,
      await readFile(path.join(repositoryRoot, file), 'utf8'),
    ]),
  ),
);
const { boundaryViolations, cycles, graph, parseFailures } = analyzeModuleGraph({
  allowedWorkspaceDependency,
  contentsByFile,
  internalPackages,
  sourceFiles,
  workspaceRoots,
});

function functionName(node, sourceFile) {
  if (node.name?.getText(sourceFile)) return node.name.getText(sourceFile);
  if (ts.isVariableDeclaration(node.parent) && node.parent.name) {
    return node.parent.name.getText(sourceFile);
  }
  if (ts.isPropertyAssignment(node.parent) && node.parent.name) {
    return node.parent.name.getText(sourceFile);
  }
  const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
  return `<anonymous>@${line}`;
}

function calculateComplexity(node) {
  let score = 1;
  function visit(child) {
    if (child !== node && ts.isFunctionLike(child)) return;
    if (
      ts.isIfStatement(child) ||
      ts.isForStatement(child) ||
      ts.isForInStatement(child) ||
      ts.isForOfStatement(child) ||
      ts.isWhileStatement(child) ||
      ts.isDoStatement(child) ||
      ts.isCatchClause(child) ||
      ts.isConditionalExpression(child) ||
      (ts.isCaseClause(child) && child.expression !== undefined)
    ) {
      score += 1;
    } else if (
      ts.isBinaryExpression(child) &&
      [
        ts.SyntaxKind.AmpersandAmpersandToken,
        ts.SyntaxKind.BarBarToken,
        ts.SyntaxKind.QuestionQuestionToken,
      ].includes(child.operatorToken.kind)
    ) {
      score += 1;
    }
    ts.forEachChild(child, visit);
  }
  ts.forEachChild(node, visit);
  return score;
}

const functions = [];
for (const file of sourceFiles) {
  const contents = contentsByFile.get(file);
  const sourceFile = ts.createSourceFile(
    file,
    contents,
    ts.ScriptTarget.Latest,
    true,
    file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
  function visit(node) {
    if (ts.isFunctionLike(node) && node.body !== undefined) {
      const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
      functions.push({
        complexity: calculateComplexity(node),
        file,
        line,
        name: functionName(node, sourceFile),
      });
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
}
functions.sort(
  (left, right) =>
    left.file.localeCompare(right.file) ||
    left.line - right.line ||
    left.name.localeCompare(right.name),
);

const baseline = await readJson('verification/baseline.json');
const baselineCycles = new Set(baseline.moduleGraph.cycles);
const newCycles = cycles.filter((cycle) => !baselineCycles.has(cycle));
const findings = [
  ...boundaryViolations.map((finding) => ({
    ...finding,
    rule: 'workspace-boundary',
  })),
  ...parseFailures.map((finding) => ({ ...finding, rule: 'parse-failure' })),
  ...newCycles.map((cycle) => ({ cycle, rule: 'new-dependency-cycle' })),
];
const complexityValues = functions.map((item) => item.complexity);
const report = {
  complexity: {
    average:
      complexityValues.length === 0
        ? 0
        : Number(
            (
              complexityValues.reduce((sum, value) => sum + value, 0) / complexityValues.length
            ).toFixed(3),
          ),
    functions,
    maximum: complexityValues.length === 0 ? 0 : Math.max(...complexityValues),
  },
  findings,
  graph: [...graph.entries()].map(([source, targets]) => ({
    source,
    targets: [...targets].sort(),
  })),
  moduleCount: sourceFiles.length,
  moduleGraph: { cycles, newCycles },
  status: findings.length === 0 ? 'PASS' : 'FAIL',
};

const outputArgument = process.argv.indexOf('--output');
const output =
  outputArgument >= 0
    ? process.argv[outputArgument + 1]
    : '.artifacts/verification/source-analysis.json';
await writeJson(output, report);

if (findings.length > 0) {
  for (const finding of findings) {
    console.error(
      `${finding.rule}: ${finding.file ?? finding.cycle} ${finding.reason ?? ''}`.trim(),
    );
  }
  process.exit(1);
}

console.log(
  `Source graph passed with ${sourceFiles.length} modules and no new cycles or boundary violations.`,
);

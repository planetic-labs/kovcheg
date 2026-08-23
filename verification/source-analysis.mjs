import { readFile } from 'node:fs/promises';
import path from 'node:path';

import ts from 'typescript';

import { readJson, repositoryRoot, walkFiles, writeJson } from './lib.mjs';

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
      walkFiles(directory, (file) => /\.(?:ts|tsx)$/.test(file)),
    ),
  )
)
  .flat()
  .filter(
    (file) =>
      file.includes('/src/') &&
      !/\.spec\.tsx?$/.test(file) &&
      !/\.integration-check\.tsx?$/.test(file) &&
      !file.includes('/src/testing/'),
  )
  .sort();
const sourceFileSet = new Set(sourceFiles);

function workspaceFor(file) {
  return workspaceRoots.find((workspace) => file === workspace || file.startsWith(`${workspace}/`));
}

function resolveRelativeImport(sourceFile, specifier) {
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(sourceFile), specifier));
  const candidates = [base, `${base}.ts`, `${base}.tsx`, `${base}/index.ts`, `${base}/index.tsx`];
  return candidates.find((candidate) => sourceFileSet.has(candidate));
}

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

const graph = new Map(sourceFiles.map((file) => [file, new Set()]));
const boundaryViolations = [];
const parseFailures = [];

for (const file of sourceFiles) {
  const contents = await readFile(path.join(repositoryRoot, file), 'utf8');
  const imports = ts.preProcessFile(contents, true, true).importedFiles;
  const sourceWorkspace = workspaceFor(file);
  for (const imported of imports) {
    const specifier = imported.fileName;
    let target;
    if (specifier.startsWith('.')) {
      target = resolveRelativeImport(file, specifier);
      if (target === undefined) continue;
    } else if (internalPackages.has(specifier)) {
      target = internalPackages.get(specifier);
    } else if (specifier.startsWith('@kovcheg/')) {
      boundaryViolations.push({
        file,
        reason: `unrecognized internal workspace import ${specifier}`,
      });
      continue;
    } else {
      continue;
    }

    if (!sourceFileSet.has(target)) {
      if (target.includes('/src/testing/')) {
        boundaryViolations.push({
          file,
          reason: `production source imports test-only entrypoint ${specifier}`,
        });
      }
      continue;
    }

    const targetWorkspace = workspaceFor(target);
    if (!allowedWorkspaceDependency(sourceWorkspace, targetWorkspace)) {
      boundaryViolations.push({
        file,
        reason: `${sourceWorkspace} cannot depend on ${targetWorkspace}`,
        target,
      });
    }
    graph.get(file).add(target);
  }

  const sourceFile = ts.createSourceFile(
    file,
    contents,
    ts.ScriptTarget.Latest,
    true,
    file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
  for (const diagnostic of sourceFile.parseDiagnostics) {
    parseFailures.push({ file, message: diagnostic.messageText });
  }
}

let index = 0;
const indexes = new Map();
const lowLinks = new Map();
const stack = [];
const onStack = new Set();
const components = [];

function connect(node) {
  indexes.set(node, index);
  lowLinks.set(node, index);
  index += 1;
  stack.push(node);
  onStack.add(node);

  for (const target of graph.get(node)) {
    if (!indexes.has(target)) {
      connect(target);
      lowLinks.set(node, Math.min(lowLinks.get(node), lowLinks.get(target)));
    } else if (onStack.has(target)) {
      lowLinks.set(node, Math.min(lowLinks.get(node), indexes.get(target)));
    }
  }

  if (lowLinks.get(node) === indexes.get(node)) {
    const component = [];
    let member;
    do {
      member = stack.pop();
      onStack.delete(member);
      component.push(member);
    } while (member !== node);
    components.push(component.sort());
  }
}

for (const node of sourceFiles) {
  if (!indexes.has(node)) connect(node);
}

const cycles = components
  .filter((component) => component.length > 1 || graph.get(component[0]).has(component[0]))
  .map((component) => component.join(' -> '))
  .sort();

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
  const contents = await readFile(path.join(repositoryRoot, file), 'utf8');
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

import path from 'node:path';

import ts from 'typescript';

function workspaceFor(file, workspaceRoots) {
  return workspaceRoots.find((workspace) => file === workspace || file.startsWith(`${workspace}/`));
}

export function resolveRelativeImport(sourceFile, specifier, sourceFileSet) {
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(sourceFile), specifier));
  const candidates = [base];

  if (base.endsWith('.mjs')) {
    candidates.push(`${base.slice(0, -4)}.mts`);
  } else if (base.endsWith('.cjs')) {
    candidates.push(`${base.slice(0, -4)}.cts`);
  } else if (base.endsWith('.js')) {
    const stem = base.slice(0, -3);
    candidates.push(`${stem}.ts`, `${stem}.tsx`);
  } else if (path.posix.extname(base) === '') {
    candidates.push(
      `${base}.ts`,
      `${base}.tsx`,
      `${base}.mts`,
      `${base}.cts`,
      `${base}/index.ts`,
      `${base}/index.tsx`,
      `${base}/index.mts`,
      `${base}/index.cts`,
    );
  }

  return candidates.find((candidate) => sourceFileSet.has(candidate));
}

function stronglyConnectedComponents(graph, sourceFiles) {
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
  return components;
}

export function analyzeModuleGraph({
  allowedWorkspaceDependency,
  contentsByFile,
  internalPackages,
  sourceFiles,
  workspaceRoots,
}) {
  const sortedSourceFiles = [...sourceFiles].sort();
  const sourceFileSet = new Set(sortedSourceFiles);
  const graph = new Map(sortedSourceFiles.map((file) => [file, new Set()]));
  const boundaryViolations = [];
  const parseFailures = [];

  for (const file of sortedSourceFiles) {
    const contents = contentsByFile.get(file);
    const imports = ts.preProcessFile(contents, true, true).importedFiles;
    const sourceWorkspace = workspaceFor(file, workspaceRoots);
    for (const imported of imports) {
      const specifier = imported.fileName;
      let target;
      if (specifier.startsWith('.')) {
        target = resolveRelativeImport(file, specifier, sourceFileSet);
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

      const targetWorkspace = workspaceFor(target, workspaceRoots);
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

  const cycles = stronglyConnectedComponents(graph, sortedSourceFiles)
    .filter((component) => component.length > 1 || graph.get(component[0]).has(component[0]))
    .map((component) => component.join(' -> '))
    .sort();

  return { boundaryViolations, cycles, graph, parseFailures };
}

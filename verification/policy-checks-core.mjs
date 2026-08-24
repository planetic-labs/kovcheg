import path from 'node:path';

import ts from 'typescript';

const vitestRoots = new Set(['describe', 'it', 'suite', 'test']);
const prohibitedModifiers = new Set(['only', 'skip', 'skipIf', 'todo']);
const objectFlags = new Set(['only', 'skip', 'todo']);

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

function expressionSegments(expression) {
  if (ts.isIdentifier(expression)) return [expression.text];
  if (ts.isPropertyAccessExpression(expression)) {
    return [...expressionSegments(expression.expression), expression.name.text];
  }
  if (
    ts.isElementAccessExpression(expression) &&
    (ts.isStringLiteral(expression.argumentExpression) ||
      ts.isNoSubstitutionTemplateLiteral(expression.argumentExpression))
  ) {
    return [...expressionSegments(expression.expression), expression.argumentExpression.text];
  }
  if (ts.isCallExpression(expression)) return expressionSegments(expression.expression);
  return [];
}

function propertyName(property) {
  if (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name))
    return property.name.text;
  return null;
}

function isDisabledLiteral(initializer) {
  return initializer?.kind === ts.SyntaxKind.FalseKeyword;
}

export function scanPolicyFile(file, contents) {
  const findings = [];
  const lines = contents.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    for (const rule of suppressionRules) {
      if (rule.marker.test(line) && !rule.justified(line)) {
        findings.push({ file, line: index + 1, rule: rule.id });
      }
    }
  }

  if (!new Set(['.cjs', '.js', '.mjs', '.ts', '.tsx']).has(path.extname(file))) {
    return findings;
  }

  const sourceFile = ts.createSourceFile(
    file,
    contents,
    ts.ScriptTarget.Latest,
    true,
    file.endsWith('.tsx')
      ? ts.ScriptKind.TSX
      : file.endsWith('.js')
        ? ts.ScriptKind.JS
        : ts.ScriptKind.TS,
  );
  const seen = new Set();
  function addFinding(node, detail) {
    const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
    const key = `${line}:${detail}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ detail, file, line, rule: 'focused-or-skipped-test' });
  }

  function visit(node) {
    if (ts.isCallExpression(node)) {
      const segments = expressionSegments(node.expression);
      const root = segments[0];
      if (['xdescribe', 'xit', 'xtest'].includes(root)) addFinding(node, root);

      if (vitestRoots.has(root)) {
        if (!ts.isCallExpression(node.expression)) {
          for (const modifier of segments.slice(1)) {
            if (prohibitedModifiers.has(modifier)) addFinding(node, `${root}.${modifier}`);
          }
        }
        for (const argument of node.arguments) {
          if (!ts.isObjectLiteralExpression(argument)) continue;
          for (const property of argument.properties) {
            if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) {
              continue;
            }
            const name = propertyName(property);
            if (!objectFlags.has(name)) continue;
            if (ts.isPropertyAssignment(property) && isDisabledLiteral(property.initializer))
              continue;
            addFinding(property, `${root}.{${name}}`);
          }
        }
      }

      if (segments[0] === 'context' && segments.at(-1) === 'skip') {
        addFinding(node, 'context.skip');
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return findings;
}

import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { parse } from 'yaml';

import { repositoryRoot, walkFiles, writeJson } from './lib.mjs';

const workflowFiles = await walkFiles('.github/workflows', (file) => /\.ya?ml$/.test(file));
const findings = [];
const pinnedUses = [];

for (const file of workflowFiles) {
  const contents = await readFile(path.join(repositoryRoot, file), 'utf8');
  try {
    parse(contents);
  } catch (error) {
    findings.push({ file, reason: error.message, rule: 'yaml-syntax' });
    continue;
  }

  if (/\bpull_request_target\s*:/.test(contents)) {
    findings.push({ file, reason: 'pull_request_target is forbidden', rule: 'event' });
  }
  if (/\b(?:write-all|read-all)\b/.test(contents)) {
    findings.push({ file, reason: 'broad permission shortcut is forbidden', rule: 'permissions' });
  }
  if (/--privileged\b|\bprivileged\s*:\s*true\b/.test(contents)) {
    findings.push({ file, reason: 'privileged containers are forbidden', rule: 'container' });
  }
  if (/\bsecrets\.[A-Za-z0-9_]+/.test(contents)) {
    findings.push({
      file,
      reason: 'repository or production secrets are forbidden',
      rule: 'secrets',
    });
  }

  for (const [index, line] of contents.split(/\r?\n/).entries()) {
    const match = line.match(/^\s*uses:\s*([^\s#]+)(?:\s+#\s*(.+))?\s*$/);
    if (!match) continue;
    const reference = match[1];
    if (reference.startsWith('./') || reference.startsWith('docker://')) continue;
    const actionMatch = reference.match(/^([^@]+)@([0-9a-f]{40})$/);
    if (!actionMatch) {
      findings.push({
        file,
        line: index + 1,
        reason: `action is not pinned to an immutable 40-character SHA: ${reference}`,
        rule: 'immutable-action-pin',
      });
      continue;
    }
    if (!/^v\d/.test(match[2] ?? '')) {
      findings.push({
        file,
        line: index + 1,
        reason: 'immutable action pin lacks a reviewable release comment',
        rule: 'action-version-comment',
      });
    }
    pinnedUses.push({ action: actionMatch[1], file, sha: actionMatch[2] });
  }
}

const report = {
  findings,
  pinnedUses,
  status: findings.length === 0 ? 'PASS' : 'FAIL',
  workflows: workflowFiles,
};
await writeJson('.artifacts/verification/workflow-policy.json', report);

if (findings.length > 0) {
  for (const finding of findings) {
    console.error(`${finding.file}:${finding.line ?? 1} ${finding.rule}: ${finding.reason}`);
  }
  process.exit(1);
}

console.log(
  `Workflow policy passed for ${workflowFiles.length} workflows and ${pinnedUses.length} action references.`,
);

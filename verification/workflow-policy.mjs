import { readFile } from 'node:fs/promises';
import path from 'node:path';

import {
  readJson,
  repositoryRoot,
  walkFiles,
  writeJson,
} from './lib.mjs';
import { analyzeWorkflow } from './workflow-policy-core.mjs';

const workflowFiles = await walkFiles('.github/workflows', (file) => /\.ya?ml$/.test(file));
const findings = [];
const pinnedUses = [];
const uses = [];
const permissionPolicy = await readJson('verification/workflow-permissions.json');

for (const file of workflowFiles) {
  const contents = await readFile(path.join(repositoryRoot, file), 'utf8');
  const result = analyzeWorkflow({
    contents,
    file,
    permissionAllowlist: permissionPolicy.workflows[file],
  });
  findings.push(...result.findings);
  pinnedUses.push(...result.pinnedUses);
  uses.push(...result.uses.map((use) => ({ ...use, file })));
}

const report = {
  findings,
  permissionPolicy,
  pinnedUses,
  status: findings.length === 0 ? 'PASS' : 'FAIL',
  uses,
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

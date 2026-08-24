import { parse } from 'yaml';

function sortedObject(value) {
  return Object.fromEntries(
    Object.entries(value ?? {}).sort(([left], [right]) => left.localeCompare(right)),
  );
}

function sameObject(left, right) {
  return JSON.stringify(sortedObject(left)) === JSON.stringify(sortedObject(right));
}

function collectUses(value, currentPath = '$', collected = [], seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return collected;
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectUses(item, `${currentPath}[${index}]`, collected, seen));
    return collected;
  }
  for (const [key, child] of Object.entries(value)) {
    const childPath = `${currentPath}.${key}`;
    if (key === 'uses' && typeof child === 'string') {
      collected.push({ path: childPath, reference: child });
    }
    collectUses(child, childPath, collected, seen);
  }
  return collected;
}

function referenceLines(contents) {
  const byReference = new Map();
  for (const [index, line] of contents.split(/\r?\n/).entries()) {
    const match = line.match(/^\s*(?:-\s*)?uses:\s*['"]?([^'"\s#]+)['"]?(?:\s+#\s*(.+))?\s*$/);
    if (!match) continue;
    const entries = byReference.get(match[1]) ?? [];
    entries.push({ comment: match[2] ?? '', line: index + 1 });
    byReference.set(match[1], entries);
  }
  return byReference;
}

function permissionRank(value) {
  return { none: 0, read: 1, write: 2 }[value] ?? Number.POSITIVE_INFINITY;
}

function checkPermissions({ file, parsed, permissionAllowlist }) {
  const findings = [];
  if (permissionAllowlist === undefined) {
    return [
      {
        file,
        reason: 'workflow is missing from the explicit minimal permissions allowlist',
        rule: 'permissions-allowlist',
      },
    ];
  }
  if (
    parsed.permissions === null ||
    typeof parsed.permissions !== 'object' ||
    Array.isArray(parsed.permissions)
  ) {
    return [
      {
        file,
        reason: 'workflow permissions must be an explicit mapping',
        rule: 'permissions',
      },
    ];
  }
  if (!sameObject(parsed.permissions, permissionAllowlist)) {
    findings.push({
      actual: sortedObject(parsed.permissions),
      expected: sortedObject(permissionAllowlist),
      file,
      reason: 'workflow permissions differ from the explicit minimal allowlist',
      rule: 'permissions-allowlist',
    });
  }

  for (const [jobName, job] of Object.entries(parsed.jobs ?? {})) {
    if (job?.permissions === undefined) continue;
    if (
      job.permissions === null ||
      typeof job.permissions !== 'object' ||
      Array.isArray(job.permissions)
    ) {
      findings.push({
        file,
        path: `$.jobs.${jobName}.permissions`,
        reason: 'job permissions must be an explicit mapping',
        rule: 'permissions',
      });
      continue;
    }
    for (const [permission, level] of Object.entries(job.permissions)) {
      const allowedLevel = permissionAllowlist[permission];
      if (allowedLevel === undefined || permissionRank(level) > permissionRank(allowedLevel)) {
        findings.push({
          file,
          path: `$.jobs.${jobName}.permissions.${permission}`,
          reason: `${permission}: ${level} exceeds the workflow permissions allowlist`,
          rule: 'permissions-allowlist',
        });
      }
    }
  }
  return findings;
}

export function analyzeWorkflow({ contents, file, permissionAllowlist }) {
  let parsed;
  try {
    parsed = parse(contents);
  } catch (error) {
    return {
      findings: [{ file, reason: error.message, rule: 'yaml-syntax' }],
      pinnedUses: [],
      uses: [],
    };
  }

  const findings = checkPermissions({ file, parsed, permissionAllowlist });
  const uses = collectUses(parsed);
  const lines = referenceLines(contents);
  const pinnedUses = [];

  if (Object.hasOwn(parsed, 'pull_request_target')) {
    findings.push({ file, reason: 'pull_request_target is forbidden', rule: 'event' });
  }
  if (Object.hasOwn(parsed.on ?? {}, 'pull_request_target')) {
    findings.push({ file, reason: 'pull_request_target is forbidden', rule: 'event' });
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

  for (const use of uses) {
    const locations = lines.get(use.reference) ?? [];
    const location = locations.shift() ?? {};
    const findingBase = { file, line: location.line, path: use.path };
    if (use.reference.startsWith('./')) {
      pinnedUses.push({ ...findingBase, kind: 'local', reference: use.reference });
      continue;
    }
    const dockerMatch = use.reference.match(/^docker:\/\/(.+)@(sha256:[0-9a-f]{64})$/);
    if (use.reference.startsWith('docker://')) {
      if (!dockerMatch) {
        findings.push({
          ...findingBase,
          reason: `container action is not pinned to a full sha256 digest: ${use.reference}`,
          rule: 'immutable-action-pin',
        });
      } else {
        pinnedUses.push({
          ...findingBase,
          digest: dockerMatch[2],
          kind: 'container',
          reference: dockerMatch[1],
        });
      }
      continue;
    }
    const actionMatch = use.reference.match(/^([^@]+)@([0-9a-f]{40})$/);
    if (!actionMatch) {
      findings.push({
        ...findingBase,
        reason: `action or reusable workflow is not pinned to an immutable 40-character SHA: ${use.reference}`,
        rule: 'immutable-action-pin',
      });
      continue;
    }
    if (!/^v\d/.test(location.comment ?? '')) {
      findings.push({
        ...findingBase,
        reason: 'immutable action pin lacks a reviewable release comment',
        rule: 'action-version-comment',
      });
    }
    pinnedUses.push({
      ...findingBase,
      kind: 'repository',
      reference: actionMatch[1],
      sha: actionMatch[2],
    });
  }

  return { findings, pinnedUses, uses };
}

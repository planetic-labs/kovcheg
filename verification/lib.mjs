import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export const artifactRoot = path.join(repositoryRoot, '.artifacts', 'verification');

export async function readJson(relativePath) {
  return JSON.parse(await readFile(path.join(repositoryRoot, relativePath), 'utf8'));
}

export async function writeJson(relativeOrAbsolutePath, value) {
  const target = path.isAbsolute(relativeOrAbsolutePath)
    ? relativeOrAbsolutePath
    : path.join(repositoryRoot, relativeOrAbsolutePath);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export async function walkFiles(relativeDirectory, predicate = () => true) {
  const root = path.join(repositoryRoot, relativeDirectory);
  const files = [];

  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolutePath);
      } else if (entry.isFile() && predicate(absolutePath)) {
        files.push(path.relative(repositoryRoot, absolutePath));
      }
    }
  }

  await visit(root);
  return files.sort();
}

export async function fileMetadata(relativePath) {
  const absolutePath = path.join(repositoryRoot, relativePath);
  const contents = await readFile(absolutePath);
  const details = await stat(absolutePath);
  return {
    bytes: details.size,
    path: relativePath,
    sha256: createHash('sha256').update(contents).digest('hex'),
  };
}

function runMetadataCommand(command, args) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
  });
  if (result.error?.code === 'ENOENT') {
    return { status: 'TOOL_UNAVAILABLE', version: null };
  }
  if (result.status !== 0) {
    return { status: 'FAIL', version: null };
  }
  return {
    status: 'PASS',
    version: (result.stdout || result.stderr || '').trim().split(/\r?\n/, 1)[0] || null,
  };
}

function gitValue(args) {
  const result = spawnSync('git', args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
  });
  return result.status === 0 ? result.stdout.trim() : null;
}

export async function collectExecutionMetadata() {
  const packageManifest = await readJson('package.json');
  const dirtyState = gitValue(['status', '--porcelain=v1', '--untracked-files=all']);
  const declaredTools = Object.fromEntries(
    ['eslint', 'jscpd', 'knip', 'prettier', 'typescript', 'vitest', 'yaml'].map((name) => [
      name,
      packageManifest.devDependencies[name],
    ]),
  );

  return {
    generatedAt: new Date().toISOString(),
    git: {
      dirty: dirtyState === null ? null : dirtyState.length > 0,
      dirtyState: dirtyState === null ? null : dirtyState.split(/\r?\n/).filter(Boolean),
      head: gitValue(['rev-parse', 'HEAD']),
      tree: gitValue(['rev-parse', 'HEAD^{tree}']),
    },
    tools: {
      declared: declaredTools,
      docker: runMetadataCommand('docker', ['--version']),
      git: runMetadataCommand('git', ['--version']),
      node: { status: 'PASS', version: process.version.replace(/^v/, '') },
      pnpm: runMetadataCommand('corepack', ['pnpm', '--version']),
      trivy: runMetadataCommand('trivy', ['--version']),
    },
  };
}

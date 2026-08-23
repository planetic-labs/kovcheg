import { createHash } from 'node:crypto';
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

import { readdir } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

const IGNORE_DIRS = new Set([
  '.git',
  'node_modules',
  'vendor',
  'dist',
  'build',
  'target',
  '.venv',
  'venv',
  '__pycache__',
  '.tox',
  '.pnpm-store',
  'bower_components',
  'coverage',
  '.next',
  '.nuxt',
  'obj',
  'bin',
]);

export interface RepoFile {
  /** Absolute path. */
  absPath: string;
  /** Repo-relative path with forward slashes. */
  relPath: string;
  fileName: string;
}

/** Recursive listing that skips dependency/build trees. Lockfiles live at the project root of each package. */
export async function listRepoFiles(root: string): Promise<RepoFile[]> {
  const out: RepoFile[] = [];
  await walk(root, root, out);
  return out;
}

async function walk(root: string, dir: string, out: RepoFile[]): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (IGNORE_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
      await walk(root, join(dir, entry.name), out);
      continue;
    }
    if (!entry.isFile()) continue;
    const absPath = join(dir, entry.name);
    out.push({
      absPath,
      relPath: relative(root, absPath).split(sep).join('/'),
      fileName: entry.name,
    });
  }
}

export function posixDir(relPath: string): string {
  const i = relPath.lastIndexOf('/');
  return i === -1 ? '' : relPath.slice(0, i);
}

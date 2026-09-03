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
  '.terraform',
]);

export interface RepoFile {
  absPath: string;
  relPath: string;
  fileName: string;
}

export const MAX_WALK_FILES = 10_000;
export const MAX_WALK_DEPTH = 32;

/**
 * Recursive listing that skips dependency/build trees. Caps file count and
 * depth so a huge checkout cannot unbounded-walk the worker.
 */
export async function listRepoFiles(root: string): Promise<RepoFile[]> {
  const out: RepoFile[] = [];
  await walk(root, root, out, 0);
  return out;
}

async function walk(root: string, dir: string, out: RepoFile[], depth: number): Promise<void> {
  if (out.length >= MAX_WALK_FILES || depth > MAX_WALK_DEPTH) return;

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (out.length >= MAX_WALK_FILES) return;
    if (entry.isDirectory()) {
      if (IGNORE_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
      if (depth + 1 > MAX_WALK_DEPTH) continue;
      await walk(root, join(dir, entry.name), out, depth + 1);
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

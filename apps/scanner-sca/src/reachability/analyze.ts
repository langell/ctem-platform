import { lstat, readdir, readFile, stat } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { Injectable } from '@nestjs/common';
import { rootLogger } from '@ctem/observability';
import { listRepoFiles, MAX_WALK_DEPTH, MAX_WALK_FILES, type RepoFile } from '../lockfiles/walk';
import { extractGoImports, isGoSource } from './golang';
import { extractJsImports, isJavascriptSource } from './javascript';
import { extractPyImports, isPythonSource } from './python';
import {
  cargoTomlDeclaresDependencyRename,
  extractRustImports,
  isRustBuildOrVendoredPath,
  isRustSource,
} from './rust';
import {
  emptyReachabilityGraph,
  ReachabilityAnalysisError,
  type ReachabilityGraph,
  type ReachabilityLanguage,
} from './types';

const log = rootLogger.child({ component: 'sca-reachability' });

/** Same order of magnitude as lockfiles: refuse a multi-megabyte "source" file. */
export const MAX_SOURCE_BYTES = 1 * 1024 * 1024;

/**
 * Cap for the crate `src/**` walk. The shared repo walk skips `bin` / `build` /
 * `dist`, so this walk is what sees `src/bin`. Hitting the cap sets truncated.
 */
const MAX_CRATE_SRC_FILES = MAX_WALK_FILES;

/**
 * Directory names the shared repo walk does not enter. Kept here so reachability
 * can fail closed on crates hidden inside them without editing walk.ts.
 * Dot-directories are also skipped by that walk (`name.startsWith('.')`).
 */
const SHARED_WALK_SKIP_DIRS = new Set([
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

/** Skipped trees that are not first-party Rust even when they contain `.rs`. */
const IGNORED_DIR_PROBE_EXEMPT = new Set(['target', 'vendor', 'node_modules', '.git']);

export interface ReachabilityAnalyzerPort {
  analyze(workDir: string, checkDeadline?: () => boolean): Promise<ReachabilityGraph>;
}

/**
 * Builds an import/call graph from first-party source in a cloned workDir.
 *
 * Crash, timeout, unreadable root, or a run that never returns a graph must
 * throw — the scanner fails the job instead of emitting all-unknown success.
 */
@Injectable()
export class ReachabilityAnalyzer implements ReachabilityAnalyzerPort {
  async analyze(
    workDir: string,
    checkDeadline: () => boolean = () => true,
  ): Promise<ReachabilityGraph> {
    await assertReadableWorkDir(workDir);
    if (!checkDeadline()) {
      throw new ReachabilityAnalysisError('Job deadline exceeded during reachability analysis');
    }

    const files = await listRepoFiles(workDir);
    const graph = emptyReachabilityGraph();
    if (files.length >= MAX_WALK_FILES) graph.truncated = true;

    await noteCargoDependencyRenames(files, graph, checkDeadline);

    const crateSrc = await listCrateSrcRustFiles(workDir, files, graph, checkDeadline);
    await noteIgnoredRustDirs(workDir, graph, checkDeadline);
    const source = [...files.filter((file) => isFirstPartySource(file)), ...crateSrc];
    let parsed = 0;

    for (const file of source) {
      if (!checkDeadline()) {
        throw new ReachabilityAnalysisError('Job deadline exceeded during reachability analysis');
      }
      const language = languageOf(file.fileName)!;
      try {
        const size = (await stat(file.absPath)).size;
        if (size > MAX_SOURCE_BYTES) {
          graph.truncated = true;
          graph.ambiguous.add(language);
          log.warn({ file: file.relPath, size }, 'skipping oversized source file');
          continue;
        }
        const content = await readFile(file.absPath, 'utf8');
        const extracted = extractImports(language, content);
        addImported(graph, language, extracted.packages);
        if (extracted.dynamic) graph.ambiguous.add(language);
        graph.languages.add(language);
        parsed += 1;
      } catch (err) {
        if (err instanceof ReachabilityAnalysisError) throw err;
        graph.truncated = true;
        graph.ambiguous.add(language);
        log.warn({ err, file: file.relPath }, 'source parse failed — not claiming not_reachable');
      }
    }

    if (source.length > 0 && parsed === 0) {
      throw new ReachabilityAnalysisError(
        `Reachability analyzer parsed none of ${source.length} source files — refusing an all-unknown success`,
      );
    }

    return graph;
  }
}

function languageOf(fileName: string): ReachabilityLanguage | undefined {
  if (isJavascriptSource(fileName)) return 'javascript';
  if (isPythonSource(fileName)) return 'python';
  if (isGoSource(fileName)) return 'go';
  if (isRustSource(fileName)) return 'rust';
  return undefined;
}

/** `.rs` under `target/` or `vendor/` is build output or vendored, not first-party. */
function isFirstPartySource(file: Pick<RepoFile, 'fileName' | 'relPath'>): boolean {
  const language = languageOf(file.fileName);
  if (!language) return false;
  if (language === 'rust' && isRustBuildOrVendoredPath(file.relPath)) return false;
  return true;
}

function extractImports(
  language: ReachabilityLanguage,
  content: string,
): { packages: string[]; dynamic: boolean } {
  switch (language) {
    case 'javascript':
      return extractJsImports(content);
    case 'python':
      return extractPyImports(content);
    case 'go':
      return extractGoImports(content);
    case 'rust':
      return extractRustImports(content);
  }
}

function addImported(
  graph: ReachabilityGraph,
  language: ReachabilityLanguage,
  packages: string[],
): void {
  const set = graph.imported.get(language) ?? new Set<string>();
  for (const name of packages) set.add(name);
  graph.imported.set(language, set);
}

/**
 * A Cargo rename (`package = "…"`) means the ident in source may not be the
 * crates.io name. Mark Rust ambiguous; do not try to map the alias here.
 * Unreadable or oversized manifests fail closed the same way.
 */
async function noteCargoDependencyRenames(
  files: RepoFile[],
  graph: ReachabilityGraph,
  checkDeadline: () => boolean,
): Promise<void> {
  for (const file of files) {
    if (file.fileName !== 'Cargo.toml') continue;
    if (!checkDeadline()) {
      throw new ReachabilityAnalysisError('Job deadline exceeded during reachability analysis');
    }
    try {
      const size = (await stat(file.absPath)).size;
      if (size > MAX_SOURCE_BYTES) {
        graph.truncated = true;
        graph.ambiguous.add('rust');
        log.warn(
          { file: file.relPath, size },
          'skipping oversized Cargo.toml — not claiming not_reachable',
        );
        continue;
      }
      const content = await readFile(file.absPath, 'utf8');
      if (cargoTomlDeclaresDependencyRename(content)) graph.ambiguous.add('rust');
    } catch (err) {
      if (err instanceof ReachabilityAnalysisError) throw err;
      graph.truncated = true;
      graph.ambiguous.add('rust');
      log.warn({ err, file: file.relPath }, 'Cargo.toml read failed — not claiming not_reachable');
    }
  }
}

/**
 * The shared walk skips `bin`, `build`, `dist`, and dot-dirs, which hides
 * `src/bin/*.rs`. For each crate root (a directory with `Cargo.toml`), list
 * `src/**` here. Skip only `target/` and `vendor/`. Never follow a symlink;
 * every skipped symlink sets truncated.
 */
async function listCrateSrcRustFiles(
  workDir: string,
  files: RepoFile[],
  graph: ReachabilityGraph,
  checkDeadline: () => boolean,
): Promise<RepoFile[]> {
  const seen = new Set(files.map((file) => file.relPath));
  const out: RepoFile[] = [];
  for (const file of files) {
    if (file.fileName !== 'Cargo.toml') continue;
    await walkCrateSrc(
      workDir,
      join(dirname(file.absPath), 'src'),
      1,
      seen,
      out,
      graph,
      checkDeadline,
    );
  }
  return out;
}

async function walkCrateSrc(
  workDir: string,
  absDir: string,
  depth: number,
  seen: Set<string>,
  out: RepoFile[],
  graph: ReachabilityGraph,
  checkDeadline: () => boolean,
): Promise<void> {
  if (!checkDeadline()) {
    throw new ReachabilityAnalysisError('Job deadline exceeded during reachability analysis');
  }
  const kind = await pathKind(absDir);
  if (kind === 'missing') return;
  if (kind === 'symlink') {
    graph.truncated = true;
    return;
  }
  if (kind !== 'dir') return;
  if (out.length >= MAX_CRATE_SRC_FILES || depth > MAX_WALK_DEPTH) {
    graph.truncated = true;
    return;
  }

  let entries;
  try {
    entries = await readdir(absDir, { withFileTypes: true });
  } catch (err) {
    const code = fsErrorCode(err);
    if (code === 'ENOENT' || code === 'ENOTDIR') return;
    graph.truncated = true;
    log.warn({ err, dir: absDir }, 'crate src walk failed — not claiming not_reachable');
    return;
  }

  for (const entry of entries) {
    if (out.length >= MAX_CRATE_SRC_FILES) {
      graph.truncated = true;
      return;
    }
    if (!checkDeadline()) {
      throw new ReachabilityAnalysisError('Job deadline exceeded during reachability analysis');
    }
    const absPath = join(absDir, entry.name);
    const entryKind = await pathKind(absPath);
    if (entryKind === 'symlink') {
      graph.truncated = true;
      continue;
    }
    if (entryKind === 'error') {
      graph.truncated = true;
      continue;
    }
    if (entryKind === 'dir') {
      if (entry.name === 'target' || entry.name === 'vendor') continue;
      await walkCrateSrc(workDir, absPath, depth + 1, seen, out, graph, checkDeadline);
      continue;
    }
    if (entryKind !== 'file' || !isRustSource(entry.name)) continue;
    const relPath = relative(workDir, absPath).split(sep).join('/');
    if (seen.has(relPath) || isRustBuildOrVendoredPath(relPath)) continue;
    seen.add(relPath);
    out.push({ absPath, relPath, fileName: entry.name });
  }
}

/**
 * The shared walk never lists crates under `bin/`, `build/`, and the other
 * non-exempt skip dirs. If one of those holds `.rs` or `Cargo.toml`, Rust is
 * ambiguous. Symlinks are not followed; skipping one sets truncated.
 */
async function noteIgnoredRustDirs(
  workDir: string,
  graph: ReachabilityGraph,
  checkDeadline: () => boolean,
): Promise<void> {
  const budget = { seen: 0 };
  await probeVisibleTree(workDir, 0, budget, graph, checkDeadline);
}

async function probeVisibleTree(
  absDir: string,
  depth: number,
  budget: { seen: number },
  graph: ReachabilityGraph,
  checkDeadline: () => boolean,
): Promise<void> {
  if (!checkDeadline()) {
    throw new ReachabilityAnalysisError('Job deadline exceeded during reachability analysis');
  }
  if (depth > MAX_WALK_DEPTH || !takeProbeBudget(budget, graph)) {
    graph.truncated = true;
    graph.ambiguous.add('rust');
    return;
  }

  let entries;
  try {
    entries = await readdir(absDir, { withFileTypes: true });
  } catch (err) {
    const code = fsErrorCode(err);
    if (code === 'ENOENT' || code === 'ENOTDIR') return;
    graph.truncated = true;
    graph.ambiguous.add('rust');
    return;
  }

  for (const entry of entries) {
    if (!checkDeadline()) {
      throw new ReachabilityAnalysisError('Job deadline exceeded during reachability analysis');
    }
    if (!takeProbeBudget(budget, graph)) return;
    const absPath = join(absDir, entry.name);
    const kind = await pathKind(absPath);
    if (kind === 'symlink') {
      graph.truncated = true;
      continue;
    }
    if (kind === 'error') {
      graph.truncated = true;
      graph.ambiguous.add('rust');
      continue;
    }
    if (kind !== 'dir') continue;
    if (IGNORED_DIR_PROBE_EXEMPT.has(entry.name)) continue;
    if (sharedWalkSkipsDir(entry.name)) {
      if (await skippedSubtreeHasRust(absPath, depth + 1, budget, graph, checkDeadline)) {
        graph.ambiguous.add('rust');
      }
      continue;
    }
    await probeVisibleTree(absPath, depth + 1, budget, graph, checkDeadline);
  }
}

async function skippedSubtreeHasRust(
  absDir: string,
  depth: number,
  budget: { seen: number },
  graph: ReachabilityGraph,
  checkDeadline: () => boolean,
): Promise<boolean> {
  if (!checkDeadline()) {
    throw new ReachabilityAnalysisError('Job deadline exceeded during reachability analysis');
  }
  const kind = await pathKind(absDir);
  if (kind === 'symlink') {
    graph.truncated = true;
    return false;
  }
  if (kind !== 'dir') return false;
  if (depth > MAX_WALK_DEPTH || !takeProbeBudget(budget, graph)) {
    graph.truncated = true;
    graph.ambiguous.add('rust');
    return true;
  }

  let entries;
  try {
    entries = await readdir(absDir, { withFileTypes: true });
  } catch (err) {
    const code = fsErrorCode(err);
    if (code === 'ENOENT' || code === 'ENOTDIR') return false;
    graph.truncated = true;
    graph.ambiguous.add('rust');
    return true;
  }

  let found = false;
  for (const entry of entries) {
    if (!checkDeadline()) {
      throw new ReachabilityAnalysisError('Job deadline exceeded during reachability analysis');
    }
    if (!takeProbeBudget(budget, graph)) return true;
    const absPath = join(absDir, entry.name);
    const entryKind = await pathKind(absPath);
    if (entryKind === 'symlink') {
      graph.truncated = true;
      continue;
    }
    if (entryKind === 'error') {
      graph.truncated = true;
      graph.ambiguous.add('rust');
      continue;
    }
    if (entryKind === 'dir') {
      if (IGNORED_DIR_PROBE_EXEMPT.has(entry.name)) continue;
      if (await skippedSubtreeHasRust(absPath, depth + 1, budget, graph, checkDeadline)) {
        found = true;
      }
      continue;
    }
    if (entryKind === 'file' && (isRustSource(entry.name) || entry.name === 'Cargo.toml')) {
      found = true;
    }
  }
  return found;
}

function sharedWalkSkipsDir(name: string): boolean {
  return name.startsWith('.') || SHARED_WALK_SKIP_DIRS.has(name);
}

function takeProbeBudget(budget: { seen: number }, graph: ReachabilityGraph): boolean {
  budget.seen += 1;
  if (budget.seen > MAX_WALK_FILES) {
    graph.truncated = true;
    graph.ambiguous.add('rust');
    return false;
  }
  return true;
}

type PathKind = 'symlink' | 'dir' | 'file' | 'other' | 'missing' | 'error';

/** lstat, never follow. A symlink is reported as `symlink` even when it points at a directory. */
async function pathKind(absPath: string): Promise<PathKind> {
  try {
    const info = await lstat(absPath);
    if (info.isSymbolicLink()) return 'symlink';
    if (info.isDirectory()) return 'dir';
    if (info.isFile()) return 'file';
    return 'other';
  } catch (err) {
    const code = fsErrorCode(err);
    if (code === 'ENOENT' || code === 'ENOTDIR') return 'missing';
    return 'error';
  }
}

function fsErrorCode(err: unknown): string {
  if (err && typeof err === 'object' && 'code' in err) return String(err.code);
  return '';
}

async function assertReadableWorkDir(workDir: string): Promise<void> {
  try {
    const info = await stat(workDir);
    if (!info.isDirectory()) {
      throw new ReachabilityAnalysisError(`Reachability workDir is not a directory: ${workDir}`);
    }
    await readdir(workDir);
  } catch (err) {
    if (err instanceof ReachabilityAnalysisError) throw err;
    throw new ReachabilityAnalysisError(
      `Reachability analyzer could not read workDir ${workDir}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

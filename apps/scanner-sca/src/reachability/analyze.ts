import { readdir, readFile, stat } from 'node:fs/promises';
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
 * `src/**` here. Skip only `target/` and `vendor/`.
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
  if (out.length >= MAX_CRATE_SRC_FILES || depth > MAX_WALK_DEPTH) {
    graph.truncated = true;
    return;
  }
  if (!checkDeadline()) {
    throw new ReachabilityAnalysisError('Job deadline exceeded during reachability analysis');
  }

  let entries;
  try {
    entries = await readdir(absDir, { withFileTypes: true });
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? String(err.code) : '';
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
    if (entry.isDirectory()) {
      if (entry.name === 'target' || entry.name === 'vendor') continue;
      await walkCrateSrc(workDir, absPath, depth + 1, seen, out, graph, checkDeadline);
      continue;
    }
    if (!entry.isFile() || !isRustSource(entry.name)) continue;
    const relPath = relative(workDir, absPath).split(sep).join('/');
    if (seen.has(relPath) || isRustBuildOrVendoredPath(relPath)) continue;
    seen.add(relPath);
    out.push({ absPath, relPath, fileName: entry.name });
  }
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

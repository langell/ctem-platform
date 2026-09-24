import { readdir, readFile, stat } from 'node:fs/promises';
import { Injectable } from '@nestjs/common';
import { rootLogger } from '@ctem/observability';
import { listRepoFiles, MAX_WALK_FILES, type RepoFile } from '../lockfiles/walk';
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

    const source = files.filter((file) => isFirstPartySource(file));
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

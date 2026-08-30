import { readdir, readFile, stat } from 'node:fs/promises';
import { Injectable } from '@nestjs/common';
import { rootLogger } from '@ctem/observability';
import { listRepoFiles, MAX_WALK_FILES } from '../lockfiles/walk';
import { extractGoImports, isGoSource } from './golang';
import { extractJsImports, isJavascriptSource } from './javascript';
import { extractPyImports, isPythonSource } from './python';
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
  async analyze(workDir: string, checkDeadline: () => boolean = () => true): Promise<ReachabilityGraph> {
    await assertReadableWorkDir(workDir);
    if (!checkDeadline()) {
      throw new ReachabilityAnalysisError('Job deadline exceeded during reachability analysis');
    }

    const files = await listRepoFiles(workDir);
    const graph = emptyReachabilityGraph();
    if (files.length >= MAX_WALK_FILES) graph.truncated = true;

    const source = files.filter((file) => languageOf(file.fileName));
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
  return undefined;
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
  }
}

function addImported(graph: ReachabilityGraph, language: ReachabilityLanguage, packages: string[]): void {
  const set = graph.imported.get(language) ?? new Set<string>();
  for (const name of packages) set.add(name);
  graph.imported.set(language, set);
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

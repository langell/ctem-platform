import { readdir, readFile, stat } from 'node:fs/promises';
import { Injectable } from '@nestjs/common';
import { rootLogger } from '@ctem/observability';
import {
  emptySastGraph,
  isSastGraph,
  SastAnalysisError,
  type SastGraph,
} from './graph';
import { RuleEngine, type RuleMatch } from './rule-engine';
import { languageOf } from './source';
import { analyzeFile, mergeFileGraph } from './taint';
import { listRepoFiles, MAX_WALK_FILES } from './walk';

const log = rootLogger.child({ component: 'sast-analyzer' });

export const MAX_SOURCE_BYTES = 1 * 1024 * 1024;

export interface SastAnalysis {
  graph: SastGraph;
  matches: RuleMatch[];
}

export interface SastAnalyzerPort {
  analyze(workDir: string, languages: string[], checkDeadline?: () => boolean): Promise<SastAnalysis>;
}

/**
 * Walks the cloned workDir, builds an import/call + taint graph, then runs
 * built-in rules. Crash, timeout, unreadable/empty workDir, or a run that
 * never returns a graph must throw — never `{ findings: [] }` as success.
 */
@Injectable()
export class SastAnalyzer implements SastAnalyzerPort {
  constructor(private readonly rules: RuleEngine) {}

  async analyze(
    workDir: string,
    languages: string[] = [],
    checkDeadline: () => boolean = () => true,
  ): Promise<SastAnalysis> {
    await assertAnalyzableWorkDir(workDir);
    if (!checkDeadline()) {
      throw new SastAnalysisError('Job deadline exceeded during SAST analysis');
    }

    const files = await listRepoFiles(workDir);
    const graph = emptySastGraph();
    if (files.length >= MAX_WALK_FILES) graph.truncated = true;

    const source = files.filter((file) => languageOf(file.fileName));
    let parsed = 0;
    const matches: RuleMatch[] = [];

    for (const file of source) {
      if (!checkDeadline()) {
        throw new SastAnalysisError('Job deadline exceeded during SAST analysis');
      }
      try {
        const size = (await stat(file.absPath)).size;
        if (size > MAX_SOURCE_BYTES) {
          graph.truncated = true;
          log.warn({ file: file.relPath, size }, 'skipping oversized source file');
          continue;
        }
        const content = await readFile(file.absPath, 'utf8');
        const language = languageOf(file.fileName)!;
        const fileGraph = analyzeFile(file.relPath, content, language);
        mergeFileGraph(graph, file.relPath, fileGraph);
        graph.files.add(file.relPath);
        matches.push(...this.rules.matchSource(content, file.relPath, language, languages, fileGraph));
        parsed += 1;
      } catch (err) {
        if (err instanceof SastAnalysisError) throw err;
        graph.truncated = true;
        log.warn({ err, file: file.relPath }, 'source parse failed');
      }
    }

    if (source.length > 0 && parsed === 0) {
      throw new SastAnalysisError(
        `SAST analyzer parsed none of ${source.length} source files — refusing empty success`,
      );
    }

    if (!isSastGraph(graph)) {
      throw new SastAnalysisError('SAST analyzer did not produce a graph — refusing empty success');
    }

    return { graph, matches };
  }
}

async function assertAnalyzableWorkDir(workDir: string): Promise<void> {
  try {
    const info = await stat(workDir);
    if (!info.isDirectory()) {
      throw new SastAnalysisError(`SAST workDir is not a directory: ${workDir}`);
    }
    const entries = await readdir(workDir);
    if (entries.length === 0) {
      throw new SastAnalysisError(
        'SAST workDir is empty — refusing success without a checkout',
      );
    }
  } catch (err) {
    if (err instanceof SastAnalysisError) throw err;
    throw new SastAnalysisError(
      `SAST analyzer could not read workDir ${workDir}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

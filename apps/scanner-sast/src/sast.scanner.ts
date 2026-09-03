import { Injectable } from '@nestjs/common';
import {
  BaseScanner,
  CheckoutError,
  GitRepoCheckout,
  type ScanContext,
  type ScanOutcome,
} from '@ctem/scanner-sdk';
import type { RawFinding, ScanJob, ScannerType } from '@ctem/contracts';
import { SastAnalyzer } from './analyzer';
import { isSastGraph, SastAnalysisError, serializeSastGraph, verdictForMatch } from './graph';
import { RuleEngine } from './rule-engine';

/** Tenant-writable analyzer overrides — never executed, only ignored. */
export const TENANT_ANALYZER_OPTION_KEYS = [
  'script',
  'rulesYaml',
  'rulesPath',
  'patternPack',
  'customRules',
  'semgrep',
  'semgrepConfig',
  'bandit',
  'codeql',
  'eslint',
] as const;

/**
 * Static analysis over source repositories.
 *
 * Checkout uses the shared fail-closed allowlist (same as SCA). Analysis is
 * in-process built-in rules over that workDir plus an import/call and
 * taint/dataflow graph. Crash, timeout, or no graph fails the job.
 */
@Injectable()
export class SastScanner extends BaseScanner {
  readonly type: ScannerType = 'sast';
  readonly name = 'ctem-sast';
  readonly version = '0.1.0';

  constructor(
    private readonly rules: RuleEngine,
    private readonly checkout: GitRepoCheckout = new GitRepoCheckout(),
    private readonly analyzer: SastAnalyzer = new SastAnalyzer(rules),
  ) {
    super();
  }

  supports(job: ScanJob): boolean {
    return job.target.kind === 'repository';
  }

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    const ignored = tenantAnalyzerOptions(ctx.job.options);
    if (ignored.length) {
      ctx.log('ignoring tenant-supplied analyzer options', { keys: ignored });
    }

    await this.checkout.checkout(ctx);
    if (!ctx.checkDeadline()) {
      throw new SastAnalysisError('Job deadline exceeded');
    }

    const languages = Array.isArray(ctx.job.options.languages)
      ? (ctx.job.options.languages as string[])
      : [];

    let analysis;
    try {
      analysis = await this.analyzer.analyze(ctx.workDir, languages, ctx.checkDeadline);
    } catch (err) {
      if (err instanceof SastAnalysisError || err instanceof CheckoutError) throw err;
      throw new SastAnalysisError(
        `SAST analysis failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (!isSastGraph(analysis.graph)) {
      throw new SastAnalysisError('SAST analyzer did not produce a graph — refusing empty success');
    }

    const findings: RawFinding[] = analysis.matches.map((m) => ({
      externalId: `${m.rule.id}:${m.path}:${m.startLine}`,
      scannerType: 'sast' as const,
      scannerName: this.name,
      title: m.rule.name,
      description: m.rule.message,
      severity: m.rule.severity,
      identifiers: [
        { system: 'rule', value: m.rule.id },
        ...m.rule.cwe.map((c) => ({ system: 'CWE', value: c })),
      ],
      cvssVector: null,
      cvssScore: null,
      epssScore: null,
      kev: false,
      location: { path: m.path, startLine: m.startLine, endLine: m.endLine },
      fix: { available: false, guidance: m.rule.message },
      evidence: {
        snippet: m.snippet,
        dataflow: m.dataflow ?? [],
        reachability: verdictForMatch({ ruleId: m.rule.id, path: m.path, startLine: m.startLine }, analysis.graph),
      },
      raw: {},
    }));

    return {
      findings,
      rawOutput: {
        matches: analysis.matches,
        rulesApplied: this.rules.list(languages).length,
        graph: serializeSastGraph(analysis.graph),
        ignoredTenantOptions: ignored,
      },
      stats: {
        matches: analysis.matches.length,
        files: analysis.graph.files.size,
        taintFlows: analysis.graph.taintFlows.length,
      },
    };
  }
}

export function tenantAnalyzerOptions(options: Record<string, unknown>): string[] {
  return TENANT_ANALYZER_OPTION_KEYS.filter((key) => {
    const value = options[key];
    return value !== undefined && value !== null && value !== '';
  });
}

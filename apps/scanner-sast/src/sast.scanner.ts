import { Injectable } from '@nestjs/common';
import { BaseScanner, type ScanContext, type ScanOutcome } from '@ctem/scanner-sdk';
import type { RawFinding, ScanJob, ScannerType } from '@ctem/contracts';
import { RuleEngine } from './rule-engine';

/**
 * Static analysis over source repositories.
 *
 * Incremental-by-default is the goal: scan the diff on a pull request, scan the
 * full tree on a schedule. Full-tree scans on every push is how a security tool
 * becomes the slowest step in someone's CI and then gets turned off.
 */
@Injectable()
export class SastScanner extends BaseScanner {
  readonly type: ScannerType = 'sast';
  readonly name = 'ctem-sast';
  readonly version = '0.1.0';

  constructor(private readonly rules: RuleEngine) {
    super();
  }

  supports(job: ScanJob): boolean {
    return job.target.kind === 'repository';
  }

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    // TODO: shallow clone at target.ref into ctx.workDir. Use a sparse checkout
    // plus `git diff --name-only` against the base ref for incremental runs.
    const languages = (ctx.job.options.languages as string[]) ?? [];
    const matches = await this.rules.run(ctx.workDir, languages);

    const findings: RawFinding[] = matches.map((m) => ({
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
      evidence: { snippet: m.snippet, dataflow: m.dataflow ?? [] },
      raw: {},
    }));

    return {
      findings,
      rawOutput: { matches, rulesApplied: this.rules.list(languages).length },
      stats: { matches: matches.length },
    };
  }
}

import { Injectable } from '@nestjs/common';
import {
  BaseScanner,
  CheckoutError,
  GitRepoCheckout,
  type ScanContext,
  type ScanOutcome,
} from '@ctem/scanner-sdk';
import type { RawFinding, ScanJob, ScannerType } from '@ctem/contracts';
import { IacAnalyzer, IacAnalysisError } from './analyzer';
import { MisconfigRules } from './misconfig.rules';

/** Tenant-writable analyzer overrides — never executed, only ignored. */
export const TENANT_IAC_OPTION_KEYS = [
  'script',
  'rulesYaml',
  'rulesPath',
  'customRules',
  'checkov',
  'tfsec',
  'terrascan',
  'kics',
  'terraform',
  'helm',
  'kubectl',
  'docker',
] as const;

/**
 * Infrastructure-as-code misconfiguration scanning.
 *
 * Checkout uses the shared fail-closed allowlist. Analysis is in-process over
 * workDir files only (Terraform HCL, CloudFormation, k8s manifests, Helm
 * templates, Dockerfiles) with the built-in MisconfigRules pack. Any detected
 * file that fails to parse fails the job — a partial inventory must not
 * complete. Findings hang on the scanned repository / iac_stack — this scanner
 * does not mint or link cloud_resource assets from HCL.
 */
@Injectable()
export class IacScanner extends BaseScanner {
  readonly type: ScannerType = 'iac';
  readonly name = 'ctem-iac';
  readonly version = '0.1.0';

  constructor(
    private readonly rules: MisconfigRules,
    private readonly checkout: GitRepoCheckout = new GitRepoCheckout(),
    private readonly analyzer: IacAnalyzer = new IacAnalyzer(rules),
  ) {
    super();
  }

  supports(job: ScanJob): boolean {
    return job.target.kind === 'repository' || job.target.kind === 'iac_stack';
  }

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    const ignored = tenantIacOptions(ctx.job.options);
    if (ignored.length) {
      ctx.log('ignoring tenant-supplied analyzer options', { keys: ignored });
    }

    await this.checkout.checkout(ctx);
    if (!ctx.checkDeadline()) {
      throw new IacAnalysisError('Job deadline exceeded');
    }

    let analysis;
    try {
      analysis = await this.analyzer.analyze(ctx.workDir, ctx.checkDeadline);
    } catch (err) {
      if (err instanceof IacAnalysisError || err instanceof CheckoutError) throw err;
      throw new IacAnalysisError(
        `IaC analysis failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    const findings: RawFinding[] = analysis.matches.map((m) => ({
      externalId: `${m.rule.id}:${m.path}:${m.address}`,
      scannerType: 'iac' as const,
      scannerName: this.name,
      title: m.rule.title,
      description: m.rule.remediation,
      severity: m.rule.severity,
      identifiers: [{ system: 'rule', value: m.rule.id }],
      cvssVector: null,
      cvssScore: null,
      epssScore: null,
      kev: false,
      location: { path: m.path, startLine: m.startLine, resource: m.address },
      fix: { available: false, guidance: m.rule.remediation },
      evidence: { snippet: m.snippet, reachability: 'unknown' },
      raw: {},
    }));

    return {
      findings,
      rawOutput: {
        matches: analysis.matches.map((m) => ({
          ruleId: m.rule.id,
          path: m.path,
          address: m.address,
          startLine: m.startLine,
        })),
        rulesApplied: this.rules.rules.length,
        files: analysis.files,
        truncated: analysis.truncated,
        ignoredTenantOptions: ignored,
      },
      stats: {
        findings: findings.length,
        files: analysis.parsed,
        detected: analysis.detected,
      },
    };
  }
}

export function tenantIacOptions(options: Record<string, unknown>): string[] {
  return TENANT_IAC_OPTION_KEYS.filter((key) => {
    const value = options[key];
    return value !== undefined && value !== null && value !== '';
  });
}

import { Injectable } from '@nestjs/common';
import { BaseScanner, type ScanContext, type ScanOutcome } from '@ctem/scanner-sdk';
import type { RawFinding, ScanJob, ScannerType } from '@ctem/contracts';
import {
  requireAwsCredentials,
  requireAzureCredentials,
  requireGcpCredentials,
} from './credentials';
import { CspmScanError, type CloudFetch } from './cloud.fetch';
import { PostureEvaluator, type CspmProvider } from './evaluate';

/** Tenant-writable analyzer overrides — never executed, only ignored. */
export const TENANT_CSPM_OPTION_KEYS = [
  'script',
  'rulesYaml',
  'rulesPath',
  'customRules',
  'awscli',
  'awsCli',
  'gcloud',
  'az',
  'azcli',
  'terraform',
  'checkov',
  'prowler',
  'scoutsuite',
  'cloudsploit',
] as const;

/**
 * Read-only cloud posture on inventoried AWS/GCP/Azure `cloud_resource`
 * assets. Live GET/Describe against the same host allowlists as discovery.
 * `kubernetes_workload` is not claimed by `supports()` and still throws if
 * execute is invoked for it.
 */
@Injectable()
export class CspmScanner extends BaseScanner {
  readonly type: ScannerType = 'cloud_posture';
  readonly name = 'ctem-cspm';
  readonly version = '0.1.0';
  private fetchImpl: CloudFetch = globalThis.fetch.bind(globalThis);

  /** Test seam — production uses global fetch through the allowlist guard. */
  useFetch(fetchImpl: CloudFetch): this {
    this.fetchImpl = fetchImpl;
    return this;
  }

  supports(job: ScanJob): boolean {
    return job.target.kind === 'cloud_resource';
  }

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    const kind = String(ctx.job.target.kind ?? '');
    if (kind === 'kubernetes_workload') {
      throw new CspmScanError(
        "Cloud posture for 'kubernetes_workload' is not implemented — refusing empty success (no cluster inventory)",
      );
    }
    if (kind !== 'cloud_resource') {
      throw new CspmScanError(
        `Cloud posture for '${kind}' is not implemented — refusing empty success`,
      );
    }

    const ignored = tenantCspmOptions(ctx.job.options);
    if (ignored.length) {
      ctx.log('ignoring tenant-supplied analyzer options', { keys: ignored });
    }

    const target = {
      ...(ctx.job.target as Record<string, unknown>),
      ...(ctx.job.options as Record<string, unknown>),
    };
    const evaluator = new PostureEvaluator(this.fetchImpl);
    evaluator.refuseTenantEndpoints(target);

    const provider = providerOf(ctx.job.target as Record<string, unknown>);
    const resourceType = String(
      (ctx.job.target as Record<string, unknown>).resourceType ?? '',
    );
    if (!resourceType) {
      throw new CspmScanError('Cloud resource is missing resourceType — refusing empty success');
    }

    const matches = await evaluator.evaluate({
      provider,
      resourceType,
      target: ctx.job.target as Record<string, unknown>,
      credentialRef: ctx.job.credentialRef,
      requireAws: requireAwsCredentials,
      requireGcp: requireGcpCredentials,
      requireAzure: requireAzureCredentials,
    });

    const findings: RawFinding[] = matches.map((m) => ({
      externalId: `${m.ruleId}:${m.resource}`,
      scannerType: 'cloud_posture',
      scannerName: this.name,
      title: m.title,
      description: m.remediation,
      severity: m.severity,
      identifiers: [{ system: 'rule', value: m.ruleId }],
      cvssVector: null,
      cvssScore: null,
      epssScore: null,
      kev: false,
      location: { resource: m.resource },
      fix: { available: false, guidance: m.remediation },
      evidence: { ...m.evidence, reachability: 'unknown' },
      raw: {},
    }));

    return {
      findings,
      rawOutput: {
        provider,
        resourceType,
        matches: matches.map((m) => ({ ruleId: m.ruleId, resource: m.resource })),
        calls: evaluator.calls.map((c) => ({ method: c.method, url: c.url })),
        ignoredTenantOptions: ignored,
      },
      stats: { findings: findings.length, calls: evaluator.calls.length },
    };
  }
}

export function tenantCspmOptions(options: Record<string, unknown>): string[] {
  return TENANT_CSPM_OPTION_KEYS.filter((key) => {
    const value = options[key];
    return value !== undefined && value !== null && value !== '';
  });
}

export function providerOf(target: Record<string, unknown>): CspmProvider {
  const source = typeof target.source === 'string' ? target.source.toLowerCase() : '';
  const key = typeof target.externalKey === 'string' ? target.externalKey.toLowerCase() : '';
  if (source === 'aws' || key.startsWith('aws:')) return 'aws';
  if (source === 'gcp' || key.startsWith('gcp:')) return 'gcp';
  if (source === 'azure' || key.startsWith('azure:')) return 'azure';
  throw new CspmScanError(
    'Cloud posture only evaluates AWS/GCP/Azure cloud_resource assets — refusing empty success',
  );
}

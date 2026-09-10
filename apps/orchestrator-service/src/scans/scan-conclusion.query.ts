import { concludeScan, type PolicyCondition, type ScanConclusion } from '@ctem/contracts';
import type { PrismaTransaction } from '@ctem/db';

/**
 * Shared `concludeScan` loader for CI GET and GitHub Checks. Inputs must stay
 * identical so a Check conclusion cannot drift from `GET /v1/scans/:id`.
 */

export interface ScanConclusionRow {
  status: string;
  scannerType: string;
  jobs?: Array<{ assetId: string; findingCount: number | null }>;
}

export async function conclusionForScan(
  tx: PrismaTransaction,
  scan: ScanConclusionRow,
): Promise<ScanConclusion> {
  if (scan.status === 'queued' || scan.status === 'running') return 'pending';

  const jobs = scan.jobs ?? [];
  const assetIds = [...new Set(jobs.map((job) => job.assetId))];
  const expectedFindingCount = jobs.reduce((n, job) => n + (job.findingCount ?? 0), 0);

  const findings = assetIds.length
    ? await tx.finding.findMany({
        where: {
          assetId: { in: assetIds },
          scannerType: scan.scannerType,
          state: { in: ['open', 'triaged', 'in_progress'] },
        },
        include: { asset: true },
      })
    : [];

  const policies = await tx.policy.findMany({
    where: { enabled: true },
    orderBy: { priority: 'asc' },
  });

  const now = new Date();
  const exceptions = await tx.riskException.findMany({
    where: {
      revokedAt: null,
      approvedAt: { not: null },
      expiresAt: { gt: now },
      OR: [
        { scope: 'global' },
        { scope: 'finding', targetRef: { in: findings.map((row) => row.id) } },
      ],
    },
  });

  const suppressedFindingIds = new Set<string>();
  if (exceptions.some((row) => row.scope === 'global')) {
    for (const row of findings) suppressedFindingIds.add(row.id);
  } else {
    for (const row of exceptions) suppressedFindingIds.add(row.targetRef);
  }

  return concludeScan({
    status: scan.status,
    findings: findings.map((row) => ({
      id: row.id,
      severity: row.severity,
      riskScore: row.riskScore,
      kev: row.kev,
      epssScore: row.epssScore,
      fixAvailable: row.fixAvailable,
      scannerType: row.scannerType,
      asset: {
        kind: row.asset.kind,
        exposure: row.asset.exposure,
        criticality: row.asset.criticality,
        tags: row.asset.tags,
      },
    })),
    policies: policies.map((policy) => ({
      enabled: policy.enabled,
      priority: policy.priority,
      condition: policy.condition as PolicyCondition,
      actions: policy.actions,
    })),
    suppressedFindingIds,
    expectedFindingCount,
  });
}

/** Terminal GET `passed`/`failed` → Checks API conclusion. `pending` is not published. */
export function checkConclusionFromScan(conclusion: ScanConclusion): 'success' | 'failure' | null {
  if (conclusion === 'passed') return 'success';
  if (conclusion === 'failed') return 'failure';
  return null;
}

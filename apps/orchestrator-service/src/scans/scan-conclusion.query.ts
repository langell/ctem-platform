import {
  concludeDeploy,
  concludeScan,
  type PolicyCondition,
  type ScanConclusion,
  type ScanDeployConclusion,
} from '@ctem/contracts';
import type { PrismaTransaction } from '@ctem/db';

/**
 * Shared loaders for CI GET, GitHub Checks, GitLab Commit Statuses, GitHub
 * Deployment statuses, and GitLab Deployment updates. Inputs must stay
 * identical so a Check or GitLab commit status cannot drift from GET
 * `conclusion` and a Deployment status cannot drift from GET
 * `deployConclusion`. Checks and GitLab Commit Statuses map `concludeScan` /
 * fail_build only; GitHub and GitLab Deployment publishers map
 * `concludeDeploy` / block_deploy only. GitLab Commit Statuses are not mapped
 * from block_deploy.
 */

export interface ScanConclusionRow {
  status: string;
  scannerType: string;
  jobs?: Array<{ assetId: string; findingCount: number | null }>;
}

export interface ScanGates {
  conclusion: ScanConclusion;
  deployConclusion: ScanDeployConclusion;
}

async function loadScanPolicyMatchInput(tx: PrismaTransaction, scan: ScanConclusionRow) {
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

  return {
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
  };
}

/** Both GET gates from one load so they cannot see different findings/policies. */
export async function scanGatesForScan(
  tx: PrismaTransaction,
  scan: ScanConclusionRow,
): Promise<ScanGates> {
  if (scan.status === 'queued' || scan.status === 'running') {
    return { conclusion: 'pending', deployConclusion: 'pending' };
  }
  const input = await loadScanPolicyMatchInput(tx, scan);
  return {
    conclusion: concludeScan(input),
    deployConclusion: concludeDeploy(input),
  };
}

/** Shared `concludeScan` loader for CI GET, GitHub Checks, and GitLab Commit Statuses. */
export async function conclusionForScan(
  tx: PrismaTransaction,
  scan: ScanConclusionRow,
): Promise<ScanConclusion> {
  const { conclusion } = await scanGatesForScan(tx, scan);
  return conclusion;
}

/** Terminal GET `passed`/`failed` → Checks API conclusion. `pending` is not published. */
export function checkConclusionFromScan(conclusion: ScanConclusion): 'success' | 'failure' | null {
  if (conclusion === 'passed') return 'success';
  if (conclusion === 'failed') return 'failure';
  return null;
}

/** Terminal GET `passed`/`failed` → GitLab Commit Status `state`. `pending` is not published. */
export function gitlabCommitStatusFromScan(conclusion: ScanConclusion): 'success' | 'failed' | null {
  if (conclusion === 'passed') return 'success';
  if (conclusion === 'failed') return 'failed';
  return null;
}

/** Shared `concludeDeploy` loader for CI GET and GitHub/GitLab Deployment publishers. */
export async function deployConclusionForScan(
  tx: PrismaTransaction,
  scan: ScanConclusionRow,
): Promise<ScanDeployConclusion> {
  const { deployConclusion } = await scanGatesForScan(tx, scan);
  return deployConclusion;
}

/** Terminal GET `allowed`/`blocked` → GitHub Deployments API state. `pending` is not published. */
export function deploymentStatusFromDeploy(
  deployConclusion: ScanDeployConclusion,
): 'success' | 'failure' | null {
  if (deployConclusion === 'allowed') return 'success';
  if (deployConclusion === 'blocked') return 'failure';
  return null;
}

/** Terminal GET `allowed`/`blocked` → GitLab Deployment `status`. `pending` is not published. */
export function gitlabDeploymentStatusFromDeploy(
  deployConclusion: ScanDeployConclusion,
): 'success' | 'failed' | null {
  if (deployConclusion === 'allowed') return 'success';
  if (deployConclusion === 'blocked') return 'failed';
  return null;
}

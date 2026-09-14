import { Injectable } from '@nestjs/common';
import type { ScanDeployConclusion } from '@ctem/contracts';
import { PrismaService } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import { resolveChecksGithubToken, type ChecksTokenPick } from './github-checks.credential';
import {
  parseGithubDeploymentsContext,
  type GithubDeploymentsContext,
} from './github-deployments.context';
import { allowlistedGithubApiUrl, deploymentStatusesUrl } from './github-deployments.egress';
import { deployConclusionForScan, deploymentStatusFromDeploy } from './scan-conclusion.query';

type PreparedPublish =
  | { skip: 'missing-scan' | 'missing-context' | 'pending-conclusion' }
  | {
      skip: null;
      ctx: GithubDeploymentsContext;
      state: 'success' | 'failure';
      token: ChecksTokenPick;
      deployConclusion: ScanDeployConclusion;
    };

const GITHUB_API_VERSION = '2022-11-28';
const USER_AGENT = 'ctem-platform';
const DESCRIPTION_MAX = 140;

/**
 * Idempotency for Deployment statuses (GitHub is create-only — no PATCH):
 *   - `description` always contains `scanId` (`CTEM scan <uuid> …`)
 *   - optional `log_url` is the CTEM scan URL when allowlisted
 *
 * Same scanId lists existing statuses and SKIPs a second POST when description
 * includes that scanId or `log_url` matches. A second replica with `GITHUB_*`
 * + context therefore does not create unbounded statuses.
 */
export interface DeploymentStatusBody {
  state: 'success' | 'failure';
  description: string;
  environment?: string;
  log_url?: string;
}

export function buildDeploymentStatusBody(
  ctx: GithubDeploymentsContext,
  scanId: string,
  state: 'success' | 'failure',
): DeploymentStatusBody {
  const gate = state === 'failure' ? 'blocked' : 'allowed';
  const prefix = `CTEM scan ${scanId} ${gate}`;
  const description = ctx.description ? `${prefix}: ${ctx.description}`.slice(0, DESCRIPTION_MAX) : prefix;
  return {
    state,
    description,
    ...(ctx.environment ? { environment: ctx.environment } : {}),
    ...(ctx.logUrl ? { log_url: ctx.logUrl } : {}),
  };
}

async function githubJson(
  url: string,
  token: string,
  init: { method: string; body?: string },
): Promise<{ ok: boolean; status: number; json: unknown }> {
  const dest = allowlistedGithubApiUrl(url);
  const res = await fetch(dest, {
    method: init.method,
    body: init.body,
    headers: {
      accept: 'application/vnd.github+json',
      'x-github-api-version': GITHUB_API_VERSION,
      'user-agent': USER_AGENT,
      authorization: `Bearer ${token}`,
      ...(init.body ? { 'content-type': 'application/json' } : {}),
    },
    signal: AbortSignal.timeout(20_000),
  });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  return { ok: res.ok, status: res.status, json };
}

function existingStatusForScan(json: unknown, scanId: string, logUrl?: string): boolean {
  const rows = Array.isArray(json) ? json : [];
  for (const raw of rows) {
    if (!raw || typeof raw !== 'object') continue;
    const row = raw as { description?: unknown; log_url?: unknown };
    if (typeof row.description === 'string' && row.description.includes(scanId)) return true;
    if (logUrl && typeof row.log_url === 'string' && row.log_url === logUrl) return true;
  }
  return false;
}

export async function publishDeploymentStatus(args: {
  ctx: GithubDeploymentsContext;
  scanId: string;
  state: 'success' | 'failure';
  token: string;
}): Promise<{ method: 'POST' | 'SKIP'; url: string; body: DeploymentStatusBody }> {
  const body = buildDeploymentStatusBody(args.ctx, args.scanId, args.state);
  const url = deploymentStatusesUrl(args.ctx.owner, args.ctx.repo, args.ctx.deploymentId);
  const listed = await githubJson(url, args.token, { method: 'GET' });
  if (!listed.ok) {
    throw new Error(`GitHub Deployment statuses GET returned ${listed.status}`);
  }
  if (existingStatusForScan(listed.json, args.scanId, args.ctx.logUrl)) {
    return { method: 'SKIP', url, body };
  }

  const created = await githubJson(url, args.token, {
    method: 'POST',
    body: JSON.stringify(body),
  });
  if (!created.ok) {
    throw new Error(`GitHub Deployment statuses POST returned ${created.status}`);
  }
  return { method: 'POST', url, body };
}

@Injectable()
export class GithubDeploymentsPublisher {
  private readonly log = rootLogger.child({ component: 'github-deployments' });

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Soft-fail publish after a scan is terminal. Missing context or unusable
   * credentials skip the Deployment call (log) and never roll back scan status
   * or change GET `deployConclusion`. Org is the scan row / signed event org —
   * never a client header.
   */
  async publishForCompletedScan(orgId: string, scanId: string): Promise<void> {
    try {
      await this.publish(orgId, scanId);
    } catch (err) {
      this.log.warn(
        { err, orgId, scanId },
        'GitHub Deployment status publish failed — leaving scan status and GET deployConclusion unchanged',
      );
    }
  }

  private async publish(orgId: string, scanId: string): Promise<void> {
    const prepared: PreparedPublish = await this.prisma.withOrg(orgId, async (tx) => {
      const scan = await tx.scan.findUnique({
        where: { id: scanId },
        include: {
          jobs: {
            include: {
              asset: {
                include: { integration: { select: { credentialRef: true } } },
              },
            },
          },
        },
      });
      if (!scan) {
        return { skip: 'missing-scan' as const };
      }

      const ctx = parseGithubDeploymentsContext(scan.options, scan.id);
      if (!ctx) {
        return { skip: 'missing-context' as const };
      }

      const deployConclusion = await deployConclusionForScan(tx, scan);
      const state = deploymentStatusFromDeploy(deployConclusion);
      if (!state) {
        return { skip: 'pending-conclusion' as const };
      }

      const refs = scan.jobs.map((job) => job.asset.integration?.credentialRef ?? null);
      const token = resolveChecksGithubToken(refs);
      return { skip: null, ctx, state, token, deployConclusion };
    });

    if (prepared.skip) {
      const skipLog: Record<typeof prepared.skip, string> = {
        'missing-scan': 'GitHub Deployment status skipped — scan not visible in org',
        'missing-context':
          'GitHub Deployment status skipped — no valid repository+deploymentId context (GET deployConclusion unchanged)',
        'pending-conclusion':
          'GitHub Deployment status skipped — concludeDeploy is still pending (GET deployConclusion unchanged)',
      };
      this.log.info({ orgId, scanId }, skipLog[prepared.skip]);
      return;
    }

    if (!prepared.token.ok) {
      this.log.warn(
        { orgId, scanId, reason: prepared.token.reason },
        'GitHub Deployment status skipped — GITHUB_* credentials unusable (fail closed; GET deployConclusion unchanged)',
      );
      return;
    }

    const result = await publishDeploymentStatus({
      ctx: prepared.ctx,
      scanId,
      state: prepared.state,
      token: prepared.token.token,
    });
    this.log.info(
      {
        orgId,
        scanId,
        method: result.method,
        url: result.url,
        deploymentState: result.body.state,
        deployConclusion: prepared.deployConclusion,
        credentialRef: prepared.token.ref,
      },
      result.method === 'SKIP'
        ? 'GitHub Deployment status already published for this scanId — skipped duplicate POST'
        : 'GitHub Deployment status published',
    );
  }
}

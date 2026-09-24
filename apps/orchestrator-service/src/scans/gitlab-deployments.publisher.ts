import { Injectable } from '@nestjs/common';
import type { ScanDeployConclusion } from '@ctem/contracts';
import { PrismaService } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import { resolveStatusesGitlabToken, type GitlabTokenPick } from './gitlab-statuses.credential';
import {
  parseGitlabDeploymentsContext,
  type GitlabDeploymentsContext,
} from './gitlab-deployments.context';
import {
  allowlistedGitLabApiUrl,
  gitLabOriginFromScanJobs,
  gitlabDeploymentUrl,
  type GitLabOrigin,
} from './gitlab-deployments.egress';
import { EGRESS_GITLAB_API, publisherEgressJson } from './publisher-egress';
import { deployConclusionForScan, gitlabDeploymentStatusFromDeploy } from './scan-conclusion.query';

type PreparedPublish =
  | { skip: 'missing-scan' | 'missing-context' | 'pending-conclusion' }
  | {
      skip: null;
      ctx: GitlabDeploymentsContext;
      origin: GitLabOrigin;
      status: 'success' | 'failed';
      token: GitlabTokenPick;
      deployConclusion: ScanDeployConclusion;
    };

const USER_AGENT = 'ctem-platform';

/**
 * Idempotency for GitLab Deployments (update-only — never POST create):
 *   - tenant supplies an existing `deploymentId`
 *   - GET that deployment; SKIP the PUT when `status` already matches
 *
 * Same terminal status therefore does not flap the deployment unbounded. A
 * second replica with `GITLAB_*` + context sees the matching status and skips.
 */
export interface DeploymentUpdateBody {
  status: 'success' | 'failed';
}

export function buildDeploymentUpdateBody(status: 'success' | 'failed'): DeploymentUpdateBody {
  return { status };
}

function currentDeploymentStatus(json: unknown): string | null {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return null;
  const status = (json as { status?: unknown }).status;
  return typeof status === 'string' ? status : null;
}

async function gitlabJson(
  url: string,
  origin: GitLabOrigin,
  token: string,
  init: { method: 'GET' | 'PUT'; body?: string },
): Promise<{ ok: boolean; status: number; json: unknown }> {
  const dest = allowlistedGitLabApiUrl(url, origin);
  return publisherEgressJson(EGRESS_GITLAB_API, dest, {
    method: init.method,
    body: init.body,
    headers: {
      accept: 'application/json',
      'user-agent': USER_AGENT,
      authorization: `Bearer ${token}`,
      ...(init.body ? { 'content-type': 'application/json' } : {}),
    },
  });
}

export async function publishGitlabDeployment(args: {
  ctx: GitlabDeploymentsContext;
  origin: GitLabOrigin;
  status: 'success' | 'failed';
  token: string;
}): Promise<{ method: 'PUT' | 'SKIP'; url: string; body: DeploymentUpdateBody }> {
  const body = buildDeploymentUpdateBody(args.status);
  const url = gitlabDeploymentUrl(args.origin, args.ctx.projectId, args.ctx.deploymentId);
  const existing = await gitlabJson(url, args.origin, args.token, { method: 'GET' });
  if (!existing.ok) {
    throw new Error(`GitLab Deployment GET returned ${existing.status}`);
  }
  if (currentDeploymentStatus(existing.json) === body.status) {
    return { method: 'SKIP', url, body };
  }

  const updated = await gitlabJson(url, args.origin, args.token, {
    method: 'PUT',
    body: JSON.stringify(body),
  });
  if (!updated.ok) {
    throw new Error(`GitLab Deployment PUT returned ${updated.status}`);
  }
  return { method: 'PUT', url, body };
}

@Injectable()
export class GitlabDeploymentsPublisher {
  private readonly log = rootLogger.child({ component: 'gitlab-deployments' });

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Soft-fail publish after a scan is terminal. Missing context or unusable
   * credentials skip the GitLab call (log) and never roll back scan status or
   * change GET `deployConclusion`. HTTP uses `@ctem/resilience`
   * (`egress:gitlab-api`): an open circuit or exhausted retry budget is the
   * same soft-fail. Org is the scan row / signed event org — never a client
   * header. Not mapped from `fail_build` / concludeScan. Never POSTs a GitLab
   * Deployment.
   */
  async publishForCompletedScan(orgId: string, scanId: string): Promise<void> {
    try {
      await this.publish(orgId, scanId);
    } catch (err) {
      this.log.warn(
        { err, orgId, scanId },
        'GitLab Deployment publish failed — leaving scan status and GET deployConclusion unchanged',
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
                include: {
                  integration: { select: { credentialRef: true, provider: true, config: true } },
                },
              },
            },
          },
        },
      });
      if (!scan) {
        return { skip: 'missing-scan' as const };
      }

      const ctx = parseGitlabDeploymentsContext(scan.options);
      if (!ctx) {
        return { skip: 'missing-context' as const };
      }

      const deployConclusion = await deployConclusionForScan(tx, scan);
      const status = gitlabDeploymentStatusFromDeploy(deployConclusion);
      if (!status) {
        return { skip: 'pending-conclusion' as const };
      }

      const origin = gitLabOriginFromScanJobs(scan.jobs);
      const refs = scan.jobs.map((job) => job.asset.integration?.credentialRef ?? null);
      const token = resolveStatusesGitlabToken(refs);
      return { skip: null, ctx, origin, status, token, deployConclusion };
    });

    if (prepared.skip) {
      const skipLog: Record<typeof prepared.skip, string> = {
        'missing-scan': 'GitLab Deployment skipped — scan not visible in org',
        'missing-context':
          'GitLab Deployment skipped — no valid projectId+deploymentId context (GET deployConclusion unchanged)',
        'pending-conclusion':
          'GitLab Deployment skipped — concludeDeploy is still pending (GET deployConclusion unchanged)',
      };
      this.log.info({ orgId, scanId }, skipLog[prepared.skip]);
      return;
    }

    if (!prepared.token.ok) {
      this.log.warn(
        { orgId, scanId, reason: prepared.token.reason },
        'GitLab Deployment skipped — GITLAB_* credentials unusable (fail closed; GET deployConclusion unchanged)',
      );
      return;
    }

    const result = await publishGitlabDeployment({
      ctx: prepared.ctx,
      origin: prepared.origin,
      status: prepared.status,
      token: prepared.token.token,
    });
    this.log.info(
      {
        orgId,
        scanId,
        method: result.method,
        url: result.url,
        host: prepared.origin.host,
        deploymentStatus: result.body.status,
        deployConclusion: prepared.deployConclusion,
        environment: prepared.ctx.environment,
        credentialRef: prepared.token.ref,
      },
      result.method === 'SKIP'
        ? 'GitLab Deployment already at this terminal status — skipped duplicate PUT'
        : 'GitLab Deployment status updated',
    );
  }
}

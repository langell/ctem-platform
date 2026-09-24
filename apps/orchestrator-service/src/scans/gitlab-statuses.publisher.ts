import { Injectable } from '@nestjs/common';
import type { ScanConclusion } from '@ctem/contracts';
import { PrismaService } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import { resolveStatusesGitlabToken, type GitlabTokenPick } from './gitlab-statuses.credential';
import { parseGitlabStatusesContext, type GitlabStatusesContext } from './gitlab-statuses.context';
import {
  allowlistedGitLabApiUrl,
  createCommitStatusUrl,
  gitLabOriginFromScanJobs,
  listCommitStatusesUrl,
  type GitLabOrigin,
} from './gitlab-statuses.egress';
import { EGRESS_GITLAB_API, publisherEgressJson } from './publisher-egress';
import { conclusionForScan, gitlabCommitStatusFromScan } from './scan-conclusion.query';

type PreparedPublish =
  | { skip: 'missing-scan' | 'missing-context' | 'pending-conclusion' }
  | {
      skip: null;
      ctx: GitlabStatusesContext;
      origin: GitLabOrigin;
      state: 'success' | 'failed';
      token: GitlabTokenPick;
      conclusion: ScanConclusion;
    };

const USER_AGENT = 'ctem-platform';
const DESCRIPTION_MAX = 255;

/**
 * Idempotency for GitLab Commit Statuses (create-only — no PATCH):
 *   - stable `name` (default `CTEM`)
 *   - `description` always contains `scanId` (`CTEM scan <uuid> …`)
 *   - optional `target_url` is the CTEM scan URL when allowlisted
 *
 * Same scanId lists existing statuses for that name+sha and SKIPs a second
 * POST when description includes that scanId or `target_url` matches. A
 * second replica with `GITLAB_*` + context therefore does not create
 * unbounded statuses.
 */
export interface CommitStatusBody {
  state: 'success' | 'failed';
  name: string;
  description: string;
  target_url?: string;
  ref?: string;
}

export function buildCommitStatusBody(
  ctx: GitlabStatusesContext,
  scanId: string,
  state: 'success' | 'failed',
): CommitStatusBody {
  const gate = state === 'failed' ? 'failed' : 'passed';
  const prefix = `CTEM scan ${scanId} ${gate}`;
  const description = ctx.description ? `${prefix}: ${ctx.description}`.slice(0, DESCRIPTION_MAX) : prefix;
  return {
    state,
    name: ctx.name,
    description,
    ...(ctx.targetUrl ? { target_url: ctx.targetUrl } : {}),
    ...(ctx.ref ? { ref: ctx.ref } : {}),
  };
}

async function gitlabJson(
  url: string,
  origin: GitLabOrigin,
  token: string,
  init: { method: string; body?: string },
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

function existingStatusForScan(json: unknown, scanId: string, name: string, targetUrl?: string): boolean {
  const rows = Array.isArray(json) ? json : [];
  for (const raw of rows) {
    if (!raw || typeof raw !== 'object') continue;
    const row = raw as { name?: unknown; description?: unknown; target_url?: unknown };
    if (typeof row.name === 'string' && row.name !== name) continue;
    if (typeof row.description === 'string' && row.description.includes(scanId)) return true;
    if (targetUrl && typeof row.target_url === 'string' && row.target_url === targetUrl) return true;
  }
  return false;
}

export async function publishCommitStatus(args: {
  ctx: GitlabStatusesContext;
  origin: GitLabOrigin;
  scanId: string;
  state: 'success' | 'failed';
  token: string;
}): Promise<{ method: 'POST' | 'SKIP'; url: string; body: CommitStatusBody }> {
  const body = buildCommitStatusBody(args.ctx, args.scanId, args.state);
  const listUrl = listCommitStatusesUrl(args.origin, args.ctx.projectId, args.ctx.sha, args.ctx.name);
  const listed = await gitlabJson(listUrl, args.origin, args.token, { method: 'GET' });
  if (!listed.ok) {
    throw new Error(`GitLab Commit Status GET returned ${listed.status}`);
  }
  if (existingStatusForScan(listed.json, args.scanId, args.ctx.name, args.ctx.targetUrl)) {
    return { method: 'SKIP', url: listUrl, body };
  }

  const url = createCommitStatusUrl(args.origin, args.ctx.projectId, args.ctx.sha);
  const created = await gitlabJson(url, args.origin, args.token, {
    method: 'POST',
    body: JSON.stringify(body),
  });
  if (!created.ok) {
    throw new Error(`GitLab Commit Status POST returned ${created.status}`);
  }
  return { method: 'POST', url, body };
}

@Injectable()
export class GitlabCommitStatusPublisher {
  private readonly log = rootLogger.child({ component: 'gitlab-statuses' });

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Soft-fail publish after a scan is terminal. Missing context or unusable
   * credentials skip the GitLab call (log) and never roll back scan status or
   * change GET conclusion. HTTP uses `@ctem/resilience` (`egress:gitlab-api`):
   * an open circuit or exhausted retry budget is the same soft-fail. Org is
   * the scan row / signed event org — never a client header. Not mapped from
   * `block_deploy` / concludeDeploy.
   */
  async publishForCompletedScan(orgId: string, scanId: string): Promise<void> {
    try {
      await this.publish(orgId, scanId);
    } catch (err) {
      this.log.warn(
        { err, orgId, scanId },
        'GitLab Commit Status publish failed — leaving scan status and GET conclusion unchanged',
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

      const ctx = parseGitlabStatusesContext(scan.options, scan.id);
      if (!ctx) {
        return { skip: 'missing-context' as const };
      }

      const conclusion = await conclusionForScan(tx, scan);
      const state = gitlabCommitStatusFromScan(conclusion);
      if (!state) {
        return { skip: 'pending-conclusion' as const };
      }

      const origin = gitLabOriginFromScanJobs(scan.jobs);
      const refs = scan.jobs.map((job) => job.asset.integration?.credentialRef ?? null);
      const token = resolveStatusesGitlabToken(refs);
      return { skip: null, ctx, origin, state, token, conclusion };
    });

    if (prepared.skip) {
      const skipLog: Record<typeof prepared.skip, string> = {
        'missing-scan': 'GitLab Commit Status skipped — scan not visible in org',
        'missing-context':
          'GitLab Commit Status skipped — no valid projectId+sha context (GET conclusion unchanged)',
        'pending-conclusion':
          'GitLab Commit Status skipped — concludeScan is still pending (GET conclusion unchanged)',
      };
      this.log.info({ orgId, scanId }, skipLog[prepared.skip]);
      return;
    }

    if (!prepared.token.ok) {
      this.log.warn(
        { orgId, scanId, reason: prepared.token.reason },
        'GitLab Commit Status skipped — GITLAB_* credentials unusable (fail closed; GET conclusion unchanged)',
      );
      return;
    }

    const result = await publishCommitStatus({
      ctx: prepared.ctx,
      origin: prepared.origin,
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
        host: prepared.origin.host,
        state: result.body.state,
        scanConclusion: prepared.conclusion,
        credentialRef: prepared.token.ref,
      },
      result.method === 'SKIP'
        ? 'GitLab Commit Status already published for this scanId — skipped duplicate POST'
        : 'GitLab Commit Status published',
    );
  }
}

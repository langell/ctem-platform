import { Injectable } from '@nestjs/common';
import type { ScanConclusion } from '@ctem/contracts';
import { PrismaService } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import {
  resolveStatusesBitbucketToken,
  type BitbucketTokenPick,
} from './bitbucket-statuses.credential';
import {
  parseBitbucketStatusesContext,
  type BitbucketStatusesContext,
} from './bitbucket-statuses.context';
import {
  allowlistedBitbucketBuildStatusUrl,
  bitbucketBuildStatusUrl,
} from './bitbucket-statuses.egress';
import { EGRESS_BITBUCKET_API, publisherEgressJson } from './publisher-egress';
import { bitbucketBuildStateFromScan, conclusionForScan } from './scan-conclusion.query';

type PreparedPublish =
  | { skip: 'missing-scan' | 'missing-context' | 'pending-conclusion' }
  | {
      skip: null;
      ctx: BitbucketStatusesContext;
      state: 'SUCCESSFUL' | 'FAILED';
      token: BitbucketTokenPick;
      conclusion: ScanConclusion;
    };

const USER_AGENT = 'ctem-platform';
const DESCRIPTION_MAX = 255;

/**
 * Idempotency for Bitbucket Cloud build statuses: the `key` is stable for a
 * scan (`ctem-scan-{scanId}` unless the scan stored a safe optional key).
 * Bitbucket upserts by `key` — a second replica POSTs the same key and does
 * not mint a distinct status. Not mapped from `block_deploy` / concludeDeploy.
 */
export interface BitbucketBuildStatusBody {
  key: string;
  state: 'SUCCESSFUL' | 'FAILED';
  name: string;
  description: string;
  url?: string;
}

export function buildBitbucketBuildStatusBody(
  ctx: BitbucketStatusesContext,
  scanId: string,
  state: 'SUCCESSFUL' | 'FAILED',
): BitbucketBuildStatusBody {
  const gate = state === 'FAILED' ? 'failed' : 'passed';
  const prefix = `CTEM scan ${scanId} ${gate}`;
  const description = ctx.description
    ? `${prefix}: ${ctx.description}`.slice(0, DESCRIPTION_MAX)
    : prefix;
  return {
    key: ctx.key,
    state,
    name: ctx.name,
    description,
    ...(ctx.url ? { url: ctx.url } : {}),
  };
}

async function bitbucketJson(
  url: string,
  workspace: string,
  repoSlug: string,
  sha: string,
  token: string,
  init: { method: string; body?: string },
): Promise<{ ok: boolean; status: number; json: unknown }> {
  const dest = allowlistedBitbucketBuildStatusUrl(url, workspace, repoSlug, sha);
  return publisherEgressJson(EGRESS_BITBUCKET_API, dest, {
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

export async function publishBitbucketBuildStatus(args: {
  ctx: BitbucketStatusesContext;
  scanId: string;
  state: 'SUCCESSFUL' | 'FAILED';
  token: string;
}): Promise<{ method: 'POST'; url: string; body: BitbucketBuildStatusBody }> {
  const body = buildBitbucketBuildStatusBody(args.ctx, args.scanId, args.state);
  const url = bitbucketBuildStatusUrl(args.ctx.workspace, args.ctx.repoSlug, args.ctx.sha);
  const created = await bitbucketJson(
    url,
    args.ctx.workspace,
    args.ctx.repoSlug,
    args.ctx.sha,
    args.token,
    {
      method: 'POST',
      body: JSON.stringify(body),
    },
  );
  if (!created.ok) {
    throw new Error(`Bitbucket build status POST returned ${created.status}`);
  }
  return { method: 'POST', url, body };
}

@Injectable()
export class BitbucketBuildStatusPublisher {
  private readonly log = rootLogger.child({ component: 'bitbucket-statuses' });

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Soft-fail publish after a scan is terminal. Missing context or unusable
   * credentials skip the Bitbucket call (log) and never roll back scan status
   * or change GET conclusion. HTTP uses `@ctem/resilience`
   * (`egress:bitbucket-api`): an open circuit or exhausted retry budget is
   * the same soft-fail. Org is the scan row / signed event org — never a
   * client header. Not mapped from `block_deploy` / concludeDeploy.
   */
  async publishForCompletedScan(orgId: string, scanId: string): Promise<void> {
    try {
      await this.publish(orgId, scanId);
    } catch (err) {
      this.log.warn(
        { err, orgId, scanId },
        'Bitbucket build status publish failed — leaving scan status and GET conclusion unchanged',
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

      const ctx = parseBitbucketStatusesContext(scan.options, scan.id);
      if (!ctx) {
        return { skip: 'missing-context' as const };
      }

      const conclusion = await conclusionForScan(tx, scan);
      const state = bitbucketBuildStateFromScan(conclusion);
      if (!state) {
        return { skip: 'pending-conclusion' as const };
      }

      const refs = scan.jobs.map((job) => job.asset.integration?.credentialRef ?? null);
      const token = resolveStatusesBitbucketToken(refs);
      return { skip: null, ctx, state, token, conclusion };
    });

    if (prepared.skip) {
      const skipLog: Record<typeof prepared.skip, string> = {
        'missing-scan': 'Bitbucket build status skipped — scan not visible in org',
        'missing-context':
          'Bitbucket build status skipped — no valid workspace+repoSlug+sha context (GET conclusion unchanged)',
        'pending-conclusion':
          'Bitbucket build status skipped — concludeScan is still pending (GET conclusion unchanged)',
      };
      this.log.info({ orgId, scanId }, skipLog[prepared.skip]);
      return;
    }

    if (!prepared.token.ok) {
      this.log.warn(
        { orgId, scanId, reason: prepared.token.reason },
        'Bitbucket build status skipped — BITBUCKET_* credentials unusable (fail closed; GET conclusion unchanged)',
      );
      return;
    }

    const result = await publishBitbucketBuildStatus({
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
        host: 'api.bitbucket.org',
        key: result.body.key,
        state: result.body.state,
        scanConclusion: prepared.conclusion,
        credentialRef: prepared.token.ref,
      },
      'Bitbucket build status published',
    );
  }
}

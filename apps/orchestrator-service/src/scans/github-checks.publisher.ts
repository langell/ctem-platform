import { Injectable } from '@nestjs/common';
import type { ScanConclusion } from '@ctem/contracts';
import { PrismaService } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import { resolveChecksGithubToken, type ChecksTokenPick } from './github-checks.credential';
import { parseGithubChecksContext, type GithubChecksContext } from './github-checks.context';
import { allowlistedGithubApiUrl, checkRunUrl, checkRunsUrl, listCheckRunsUrl } from './github-checks.egress';
import { checkConclusionFromScan, conclusionForScan } from './scan-conclusion.query';

type PreparedPublish =
  | { skip: 'missing-scan' | 'missing-context' | 'pending-conclusion' }
  | {
      skip: null;
      ctx: GithubChecksContext;
      checkConclusion: 'success' | 'failure';
      token: ChecksTokenPick;
      conclusion: ScanConclusion;
    };

const GITHUB_API_VERSION = '2022-11-28';
const USER_AGENT = 'ctem-platform';

/**
 * Idempotent identity for a Check Run:
 *   - `name` — `checkName` (default `CTEM`)
 *   - `head_sha` — commit SHA from Checks context
 *   - `external_id` — scan UUID
 *
 * Same scanId lists by name+sha, PATCHes a matching `external_id`, or POSTs once.
 * A second replica with `GITHUB_*` + context updates the same run rather than
 * creating unbounded Check Runs.
 */
export interface CheckRunBody {
  name: string;
  head_sha: string;
  status: 'completed';
  conclusion: 'success' | 'failure';
  external_id: string;
  details_url?: string;
  output: { title: string; summary: string };
}

export function buildCheckRunBody(
  ctx: GithubChecksContext,
  scanId: string,
  conclusion: 'success' | 'failure',
): CheckRunBody {
  const title = conclusion === 'failure' ? 'CTEM fail_build' : 'CTEM passed';
  const summary =
    `CTEM scan ${scanId} conclusion is ${conclusion === 'failure' ? 'failed' : 'passed'} ` +
    '(from concludeScan / fail_build policy). Scan row status is not the Check conclusion.';
  return {
    name: ctx.checkName,
    head_sha: ctx.sha,
    status: 'completed',
    conclusion,
    external_id: scanId,
    ...(ctx.detailsUrl ? { details_url: ctx.detailsUrl } : {}),
    output: { title, summary },
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

function existingCheckRunId(json: unknown, scanId: string): number | null {
  if (!json || typeof json !== 'object') return null;
  const runs = (json as { check_runs?: unknown }).check_runs;
  if (!Array.isArray(runs)) return null;
  for (const raw of runs) {
    if (!raw || typeof raw !== 'object') continue;
    const run = raw as { id?: unknown; external_id?: unknown };
    if (run.external_id === scanId && typeof run.id === 'number') return run.id;
  }
  return null;
}

export async function upsertCheckRun(args: {
  ctx: GithubChecksContext;
  scanId: string;
  conclusion: 'success' | 'failure';
  token: string;
}): Promise<{ method: 'POST' | 'PATCH'; url: string; body: CheckRunBody }> {
  const body = buildCheckRunBody(args.ctx, args.scanId, args.conclusion);
  const listUrl = listCheckRunsUrl(args.ctx.owner, args.ctx.repo, args.ctx.sha, args.ctx.checkName);
  const listed = await githubJson(listUrl, args.token, { method: 'GET' });
  const existing = listed.ok ? existingCheckRunId(listed.json, args.scanId) : null;

  if (existing != null) {
    const url = checkRunUrl(args.ctx.owner, args.ctx.repo, existing);
    const patched = await githubJson(url, args.token, {
      method: 'PATCH',
      body: JSON.stringify({
        status: body.status,
        conclusion: body.conclusion,
        ...(body.details_url ? { details_url: body.details_url } : {}),
        output: body.output,
      }),
    });
    if (!patched.ok) {
      throw new Error(`GitHub Checks PATCH returned ${patched.status}`);
    }
    return { method: 'PATCH', url, body };
  }

  const url = checkRunsUrl(args.ctx.owner, args.ctx.repo);
  const created = await githubJson(url, args.token, {
    method: 'POST',
    body: JSON.stringify(body),
  });
  if (!created.ok) {
    throw new Error(`GitHub Checks POST returned ${created.status}`);
  }
  return { method: 'POST', url, body };
}

@Injectable()
export class GithubChecksPublisher {
  private readonly log = rootLogger.child({ component: 'github-checks' });

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Soft-fail publish after a scan is terminal. Missing context or unusable
   * credentials skip the Check call (log) and never roll back scan status or
   * change GET conclusion. Org is the scan row / signed event org — never a
   * client header.
   */
  async publishForCompletedScan(orgId: string, scanId: string): Promise<void> {
    try {
      await this.publish(orgId, scanId);
    } catch (err) {
      this.log.warn(
        { err, orgId, scanId },
        'GitHub Checks publish failed — leaving scan status and GET conclusion unchanged',
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

      const ctx = parseGithubChecksContext(scan.options, scan.id);
      if (!ctx) {
        return { skip: 'missing-context' as const };
      }

      const conclusion = await conclusionForScan(tx, scan);
      const checkConclusion = checkConclusionFromScan(conclusion);
      if (!checkConclusion) {
        return { skip: 'pending-conclusion' as const };
      }

      const refs = scan.jobs.map((job) => job.asset.integration?.credentialRef ?? null);
      const token = resolveChecksGithubToken(refs);
      return { skip: null, ctx, checkConclusion, token, conclusion };
    });

    if (prepared.skip) {
      const skipLog: Record<typeof prepared.skip, string> = {
        'missing-scan': 'GitHub Checks skipped — scan not visible in org',
        'missing-context':
          'GitHub Checks skipped — no valid repository+sha context (GET conclusion unchanged)',
        'pending-conclusion':
          'GitHub Checks skipped — concludeScan is still pending (GET conclusion unchanged)',
      };
      this.log.info({ orgId, scanId }, skipLog[prepared.skip]);
      return;
    }

    if (!prepared.token.ok) {
      this.log.warn(
        { orgId, scanId, reason: prepared.token.reason },
        'GitHub Checks skipped — GITHUB_* credentials unusable (fail closed; GET conclusion unchanged)',
      );
      return;
    }

    const result = await upsertCheckRun({
      ctx: prepared.ctx,
      scanId,
      conclusion: prepared.checkConclusion,
      token: prepared.token.token,
    });
    this.log.info(
      {
        orgId,
        scanId,
        method: result.method,
        url: result.url,
        checkConclusion: result.body.conclusion,
        scanConclusion: prepared.conclusion,
        credentialRef: prepared.token.ref,
      },
      'GitHub Check Run published',
    );
  }
}

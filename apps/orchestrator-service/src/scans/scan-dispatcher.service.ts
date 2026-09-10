import { BadRequestException, Injectable, Optional } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { EventBus } from '@ctem/events';
import { SUBJECTS, ScanJob, UserId, type CreateScanRequest, type ScannerType } from '@ctem/contracts';
import { loadEnv } from '@ctem/config';
import { currentTraceId, rootLogger } from '@ctem/observability';
import { ScanPlannerService } from './scan-planner.service';
import { GithubChecksPublisher } from './github-checks.publisher';

export interface DispatchAsset {
  id: string;
  kind: string;
  externalKey: string;
  attributes: unknown;
  integrationId: string | null;
}

/** Target metadata the scanner is allowed to see — includes connector attributes. */
export function scanJobTarget(asset: Pick<DispatchAsset, 'externalKey' | 'kind' | 'attributes'>): Record<string, unknown> {
  const attrs =
    asset.attributes && typeof asset.attributes === 'object' && !Array.isArray(asset.attributes)
      ? (asset.attributes as Record<string, unknown>)
      : {};
  return {
    externalKey: asset.externalKey,
    kind: asset.kind,
    ...attrs,
  };
}

/** Pointer only — never the secret. Missing integration → null (public path). */
export function scanJobCredentialRef(
  asset: Pick<DispatchAsset, 'integrationId'>,
  refs: Map<string, string | null>,
): string | null {
  if (!asset.integrationId) return null;
  return refs.get(asset.integrationId) ?? null;
}

/**
 * Gateway JWT `userId` is `users.id` after identity resolve. IdP-shaped ids
 * (`demo|analyst`) are still classified so a stale principal cannot P2023.
 */
export function requestedByFromPrincipal(
  principalId: string | null,
): { kind: 'uuid'; id: string } | { kind: 'idp'; subject: string } | { kind: 'none' } {
  if (!principalId) return { kind: 'none' };
  const parsed = UserId.safeParse(principalId);
  if (parsed.success) return { kind: 'uuid', id: parsed.data };
  return { kind: 'idp', subject: principalId };
}

@Injectable()
export class ScanDispatcherService {
  private readonly log = rootLogger.child({ component: 'scan-dispatcher' });

  constructor(
    private readonly prisma: PrismaService,
    private readonly planner: ScanPlannerService,
    private readonly bus: EventBus,
    @Optional() private readonly checks?: GithubChecksPublisher,
  ) {}

  /**
   * Creates the scan record, then fans out one job per asset. Jobs are persisted
   * before publishing so a crash mid-dispatch leaves a scan we can resume rather
   * than a half-dispatched mystery.
   */
  async createScan(
    orgId: string,
    userId: string | null,
    request: CreateScanRequest,
    trigger: 'manual' | 'scheduled' | 'webhook' | 'ci' = 'manual',
  ) {
    const env = loadEnv();
    const assets = await this.planner.plan(
      orgId,
      request.scannerType as ScannerType,
      request.assetSelector,
    );
    const requestedBy = await this.resolveRequestedBy(userId);

    const scan = await this.prisma.withOrg(orgId, async (tx) => {
      const created = await tx.scan.create({
        data: {
          orgId,
          scannerType: request.scannerType,
          trigger,
          status: assets.length ? 'running' : 'succeeded',
          requestedBy,
          assetSelector: request.assetSelector as object,
          options: request.options as object,
          jobsTotal: assets.length,
          startedAt: new Date(),
          finishedAt: assets.length ? null : new Date(),
        },
      });

      if (assets.length) {
        await tx.scanJob.createMany({
          data: assets.map((asset) => ({
            orgId,
            scanId: created.id,
            assetId: asset.id,
            scannerType: request.scannerType,
            status: 'queued',
          })),
        });
      }
      return created;
    });

    // Jobs are already queued. Anything after this (schema, NATS, missing
    // asset) must fail the job — never turn a kick into HTTP 500.
    let jobs: Array<{ id: string; scanId: string; assetId: string; scannerType: string; attempt: number }> =
      [];
    try {
      jobs = await this.prisma.withOrg(orgId, (tx) => tx.scanJob.findMany({ where: { scanId: scan.id } }));
      const credByIntegration = await this.credentialRefsFor(orgId, assets);

      for (const job of jobs) {
        try {
          await this.publishQueuedJob({
            orgId,
            scanId: scan.id,
            job,
            asset: assets.find((a) => a.id === job.assetId),
            scannerType: request.scannerType as ScannerType,
            options: request.options,
            credByIntegration,
            timeoutMs: env.SCANNER_JOB_TIMEOUT_MS,
            causationId: scan.id,
          });
        } catch (err) {
          this.log.error({ err, jobId: job.id, scanId: scan.id }, 'scan job dispatch failed — failing job closed');
          await this.failDispatch(orgId, job, err).catch((persistErr) =>
            this.log.error({ persistErr, jobId: job.id }, 'failed to persist dispatch failure'),
          );
        }
      }
    } catch (err) {
      this.log.error(
        { err, scanId: scan.id },
        'scan dispatch failed after persist — returning queued scan rather than 500',
      );
    }

    const latest = await this.prisma
      .withOrg(orgId, (tx) => tx.scan.findUnique({ where: { id: scan.id } }))
      .catch(() => null);

    this.log.info({ scanId: scan.id, jobs: jobs.length }, 'scan dispatched');
    const row = latest ?? scan;
    // Zero-asset (already terminal) scans never emit scanCompleted via lifecycle.
    if (row.status !== 'queued' && row.status !== 'running') {
      await this.checks?.publishForCompletedScan(orgId, scan.id);
    }
    return { ...row, jobsDispatched: jobs.length };
  }

  /**
   * `users` is not RLS-scoped (global IdP directory). Lookup by `idpSubject`
   * so a Keycloak `sub` becomes `users.id`. Unmapped subjects fail-close as
   * 4xx — never 500, never an unattributed persist. Null (scheduled) and UUID
   * (PAT token id) pass through as today.
   */
  private async resolveRequestedBy(principalId: string | null): Promise<string | null> {
    const who = requestedByFromPrincipal(principalId);
    if (who.kind === 'none') return null;
    if (who.kind === 'uuid') return who.id;
    const user = await this.prisma.user.findUnique({
      where: { idpSubject: who.subject },
      select: { id: true },
    });
    if (!user) {
      throw new BadRequestException(
        `No user mapped for IdP subject — refusing scan create (idpSubject is not a users row)`,
      );
    }
    return user.id;
  }

  /** Re-dispatch a single failed job — used by retries and by manual re-runs. */
  async retryJob(orgId: string, jobId: string) {
    const job = await this.prisma.withOrg(orgId, (tx) =>
      tx.scanJob.update({
        where: { id: jobId },
        data: { status: 'queued', attempt: { increment: 1 }, error: null },
      }),
    );
    const asset = await this.prisma.withOrg(orgId, (tx) =>
      tx.asset.findUniqueOrThrow({ where: { id: job.assetId } }),
    );
    const credByIntegration = await this.credentialRefsFor(orgId, [asset]);

    try {
      await this.publishQueuedJob({
        orgId,
        scanId: job.scanId,
        job,
        asset,
        scannerType: job.scannerType as ScannerType,
        options: {},
        credByIntegration,
        timeoutMs: loadEnv().SCANNER_JOB_TIMEOUT_MS,
        causationId: job.scanId,
      });
    } catch (err) {
      this.log.error({ err, jobId: job.id }, 'retry dispatch failed — failing job closed');
      await this.failDispatch(orgId, job, err);
    }
    return job;
  }

  private async publishQueuedJob(args: {
    orgId: string;
    scanId: string;
    job: { id: string; assetId: string; attempt: number };
    asset: DispatchAsset | undefined;
    scannerType: ScannerType;
    options: Record<string, unknown>;
    credByIntegration: Map<string, string | null>;
    timeoutMs: number;
    causationId: string;
  }): Promise<void> {
    if (!args.asset) {
      throw new Error(`Scan job ${args.job.id} has no matching asset — refusing dispatch`);
    }
    const payload = ScanJob.parse({
      jobId: args.job.id,
      scanId: args.scanId,
      orgId: args.orgId,
      scannerType: args.scannerType,
      assetId: args.job.assetId,
      target: scanJobTarget(args.asset),
      // Pointer from the discovering integration — resolved by the scanner
      // via the platform-operated env: allowlist, never stored as a secret.
      credentialRef: scanJobCredentialRef(args.asset, args.credByIntegration),
      options: args.options,
      attempt: args.job.attempt,
      deadlineAt: new Date(Date.now() + args.timeoutMs),
      traceId: currentTraceId(),
    });
    await this.bus.publish(SUBJECTS.scanJobDispatched, args.orgId, payload, {
      causationId: args.causationId,
    });
  }

  /**
   * Persist a dispatch-time failure so kick is fail-closed at the job, not a
   * gateway 500. Mirrors scan-lifecycle close-out when every job has finished.
   */
  private async failDispatch(
    orgId: string,
    job: { id: string; scanId: string },
    error: unknown,
  ): Promise<void> {
    const message = error instanceof Error ? error.message : String(error);
    await this.prisma.withOrg(orgId, async (tx) => {
      await tx.scanJob.update({
        where: { id: job.id },
        data: {
          status: 'failed',
          error: message,
          startedAt: new Date(),
          finishedAt: new Date(),
        },
      });
      const updated = await tx.scan.update({
        where: { id: job.scanId },
        data: { jobsCompleted: { increment: 1 } },
      });
      if (updated.jobsCompleted < updated.jobsTotal) return;
      const failed = await tx.scanJob.count({
        where: { scanId: job.scanId, status: 'failed' },
      });
      await tx.scan.update({
        where: { id: job.scanId },
        data: {
          status: failed === 0 ? 'succeeded' : failed === updated.jobsTotal ? 'failed' : 'partial',
          finishedAt: new Date(),
        },
      });
    });
  }

  private async credentialRefsFor(
    orgId: string,
    assets: Array<{ integrationId: string | null }>,
  ): Promise<Map<string, string | null>> {
    const ids = [...new Set(assets.map((a) => a.integrationId).filter((id): id is string => Boolean(id)))];
    if (!ids.length) return new Map();
    const rows = await this.prisma.withOrg(orgId, (tx) =>
      tx.integration.findMany({
        where: { id: { in: ids } },
        select: { id: true, credentialRef: true },
      }),
    );
    return new Map(rows.map((r) => [r.id, r.credentialRef]));
  }
}

import { Injectable } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { EventBus } from '@ctem/events';
import { SUBJECTS, type CreateScanRequest, type ScanJob, type ScannerType } from '@ctem/contracts';
import { loadEnv } from '@ctem/config';
import { currentTraceId, rootLogger } from '@ctem/observability';
import { ScanPlannerService } from './scan-planner.service';

@Injectable()
export class ScanDispatcherService {
  private readonly log = rootLogger.child({ component: 'scan-dispatcher' });

  constructor(
    private readonly prisma: PrismaService,
    private readonly planner: ScanPlannerService,
    private readonly bus: EventBus,
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

    const scan = await this.prisma.withOrg(orgId, async (tx) => {
      const created = await tx.scan.create({
        data: {
          orgId,
          scannerType: request.scannerType,
          trigger,
          status: assets.length ? 'running' : 'succeeded',
          requestedBy: userId,
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

    const jobs = await this.prisma.withOrg(orgId, (tx) =>
      tx.scanJob.findMany({ where: { scanId: scan.id } }),
    );

    for (const job of jobs) {
      const asset = assets.find((a) => a.id === job.assetId)!;
      const payload: ScanJob = {
        jobId: job.id,
        scanId: scan.id,
        orgId,
        scannerType: request.scannerType as ScannerType,
        assetId: job.assetId,
        target: {
          externalKey: asset.externalKey,
          kind: asset.kind,
          ...(asset.attributes as Record<string, unknown>),
        },
        // Resolved from the secret store at dispatch time, not stored on the job.
        credentialRef: null,
        options: request.options,
        attempt: 1,
        deadlineAt: new Date(Date.now() + env.SCANNER_JOB_TIMEOUT_MS),
        traceId: currentTraceId(),
      };
      await this.bus.publish(SUBJECTS.scanJobDispatched, orgId, payload, {
        causationId: scan.id,
      });
    }

    this.log.info({ scanId: scan.id, jobs: jobs.length }, 'scan dispatched');
    return { ...scan, jobsDispatched: jobs.length };
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

    await this.bus.publish(SUBJECTS.scanJobDispatched, orgId, {
      jobId: job.id,
      scanId: job.scanId,
      orgId,
      scannerType: job.scannerType,
      assetId: job.assetId,
      target: { externalKey: asset.externalKey, kind: asset.kind },
      credentialRef: null,
      options: {},
      attempt: job.attempt,
      deadlineAt: new Date(Date.now() + loadEnv().SCANNER_JOB_TIMEOUT_MS),
      traceId: currentTraceId(),
    });
    return job;
  }
}

import { Inject, Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventBus } from '@ctem/events';
import { ArtifactStore } from '@ctem/storage';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import { SUBJECTS, ScanJob, type ScanJobResult } from '@ctem/contracts';
import { BaseScanner, SCANNER, type ScanContext } from './base-scanner';

/**
 * Consumes dispatched jobs for one scanner type, runs them with bounded
 * concurrency, and reports results back onto the bus. Workers are horizontally
 * scalable: they share a durable queue group, so adding replicas adds throughput.
 */
@Injectable()
export class ScannerWorker implements OnApplicationBootstrap {
  private readonly log = rootLogger.child({ component: 'scanner-worker' });
  private inFlight = 0;

  constructor(
    @Inject(SCANNER) private readonly scanner: BaseScanner,
    private readonly bus: EventBus,
    private readonly artifacts: ArtifactStore,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    const env = loadEnv();
    await this.scanner.onReady();

    await this.bus.subscribe(
      SUBJECTS.scanJobDispatched,
      {
        durable: `scanner-${this.scanner.type}`,
        queueGroup: `scanner-${this.scanner.type}`,
        maxDeliver: 3,
        ackWaitMs: env.SCANNER_JOB_TIMEOUT_MS + 30_000,
      },
      async (payload) => {
        const job = ScanJob.parse(payload);
        // One stream carries all scanner types; ignore what isn't ours.
        if (job.scannerType !== this.scanner.type) return;
        if (!this.scanner.supports(job)) return;
        await this.runJob(job);
      },
    );

    this.log.info(
      { scanner: this.scanner.name, type: this.scanner.type, version: this.scanner.version },
      'scanner worker ready',
    );
  }

  private async runJob(job: ScanJob): Promise<void> {
    const startedAt = new Date();
    const workDir = await mkdtemp(join(tmpdir(), `ctem-${job.scannerType}-`));
    this.inFlight += 1;

    const ctx: ScanContext = {
      job,
      workDir,
      checkDeadline: () => Date.now() < new Date(job.deadlineAt).getTime(),
      log: (msg, meta) => this.log.info({ jobId: job.jobId, ...meta }, msg),
    };

    let result: ScanJobResult;
    try {
      const outcome = await this.scanner.execute(ctx);

      let artifactKey: string | null = null;
      if (outcome.rawOutput !== undefined) {
        artifactKey = await this.artifacts.putJson(
          this.artifacts.key(job.orgId, 'scan', job.scanId, `${job.jobId}.json`),
          outcome.rawOutput,
        );
      }

      // Findings go out before the completion event so the findings service has
      // them persisted by the time the orchestrator marks the scan done.
      await this.bus.publish(SUBJECTS.findingsReported, job.orgId, {
        scanId: job.scanId,
        jobId: job.jobId,
        assetId: job.assetId,
        scannerType: job.scannerType,
        artifactKey,
        findings: outcome.findings,
      });

      result = {
        jobId: job.jobId,
        scanId: job.scanId,
        orgId: job.orgId,
        scannerType: job.scannerType,
        assetId: job.assetId,
        status: 'succeeded',
        startedAt,
        finishedAt: new Date(),
        artifactKey,
        findingCount: outcome.findings.length,
        error: null,
        stats: outcome.stats ?? {},
      };
    } catch (err) {
      this.log.error({ err, jobId: job.jobId }, 'scan job failed');
      result = {
        jobId: job.jobId,
        scanId: job.scanId,
        orgId: job.orgId,
        scannerType: job.scannerType,
        assetId: job.assetId,
        status: 'failed',
        startedAt,
        finishedAt: new Date(),
        artifactKey: null,
        findingCount: 0,
        error: err instanceof Error ? err.message : String(err),
        stats: {},
      };
    } finally {
      this.inFlight -= 1;
      await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
    }

    await this.bus.publish(SUBJECTS.scanJobCompleted, job.orgId, result);
  }

  get load(): number {
    return this.inFlight;
  }
}

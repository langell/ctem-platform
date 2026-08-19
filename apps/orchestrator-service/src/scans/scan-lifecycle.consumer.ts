import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { EventBus } from '@ctem/events';
import { SUBJECTS, ScanJobResult } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';

/**
 * Tracks job completions and closes out the parent scan. A scan with any failed
 * job finishes as `partial` rather than `succeeded` — silently dropping a failed
 * scanner is how coverage gaps go unnoticed.
 */
@Injectable()
export class ScanLifecycleConsumer implements OnApplicationBootstrap {
  private readonly log = rootLogger.child({ component: 'scan-lifecycle' });

  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: EventBus,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.bus.subscribe(
      SUBJECTS.scanJobCompleted,
      { durable: 'orchestrator-job-completed' },
      async (payload) => {
        const result = ScanJobResult.parse(payload);
        await this.applyResult(result);
      },
    );
  }

  private async applyResult(result: ScanJobResult): Promise<void> {
    const scan = await this.prisma.withOrg(result.orgId, async (tx) => {
      await tx.scanJob.update({
        where: { id: result.jobId },
        data: {
          status: result.status,
          startedAt: result.startedAt,
          finishedAt: result.finishedAt,
          artifactKey: result.artifactKey,
          findingCount: result.findingCount,
          error: result.error,
          stats: result.stats as object,
        },
      });

      const updated = await tx.scan.update({
        where: { id: result.scanId },
        data: { jobsCompleted: { increment: 1 } },
      });

      if (updated.jobsCompleted < updated.jobsTotal) return null;

      const failed = await tx.scanJob.count({
        where: { scanId: result.scanId, status: 'failed' },
      });

      return tx.scan.update({
        where: { id: result.scanId },
        data: {
          status: failed === 0 ? 'succeeded' : failed === updated.jobsTotal ? 'failed' : 'partial',
          finishedAt: new Date(),
        },
      });
    });

    if (scan) {
      await this.bus.publish(SUBJECTS.scanCompleted, result.orgId, {
        scanId: scan.id,
        status: scan.status,
      });
      this.log.info({ scanId: scan.id, status: scan.status }, 'scan completed');
    }
  }
}

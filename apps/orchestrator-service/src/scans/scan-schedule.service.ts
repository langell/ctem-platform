import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import type { ScannerType } from '@ctem/contracts';
import { ScanDispatcherService } from './scan-dispatcher.service';

/**
 * Default cadence per scanner type. "Continuous" in CTEM does not mean "run
 * everything constantly" — it means each surface is re-evaluated at a rate that
 * matches how fast it changes and how expensive it is to check.
 */
const DEFAULT_CADENCE_MS: Record<ScannerType, number> = {
  sca: 6 * 60 * 60_000, // new advisories land daily; deps change on every merge
  sast: 24 * 60 * 60_000,
  container: 12 * 60 * 60_000,
  iac: 24 * 60 * 60_000,
  secrets: 24 * 60 * 60_000,
  asm: 24 * 60 * 60_000, // external probing — be a polite neighbour
  cloud_posture: 6 * 60 * 60_000,
};

@Injectable()
export class ScanScheduleService implements OnApplicationBootstrap {
  private readonly log = rootLogger.child({ component: 'scan-schedule' });
  private timer?: NodeJS.Timeout;

  constructor(
    private readonly prisma: PrismaService,
    private readonly dispatcher: ScanDispatcherService,
  ) {}

  onApplicationBootstrap(): void {
    // TODO: leader election (or a JetStream-backed scheduler) so multiple
    // orchestrator replicas do not each fire the same scheduled scan.
    this.timer = setInterval(() => void this.tick(), 5 * 60_000);
    this.log.info('scan scheduler started');
  }

  private async tick(): Promise<void> {
    const orgs = await this.prisma.unsafeCrossTenant('scheduled scans sweep every org', (db) =>
      db.organization.findMany({ select: { id: true } }),
    );

    for (const org of orgs) {
      for (const [scannerType, cadence] of Object.entries(DEFAULT_CADENCE_MS)) {
        const last = await this.prisma.withOrg(org.id, (tx) =>
          tx.scan.findFirst({
            where: { scannerType, trigger: 'scheduled' },
            orderBy: { createdAt: 'desc' },
            select: { createdAt: true },
          }),
        );

        if (last && Date.now() - last.createdAt.getTime() < cadence) continue;

        try {
          await this.dispatcher.createScan(
            org.id,
            null,
            { scannerType: scannerType as ScannerType, assetSelector: {}, options: {} },
            'scheduled',
          );
        } catch (err) {
          this.log.error({ err, orgId: org.id, scannerType }, 'scheduled scan failed to dispatch');
        }
      }
    }
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }
}

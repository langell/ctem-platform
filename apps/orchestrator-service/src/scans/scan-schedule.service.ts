import { Inject, Injectable, OnApplicationBootstrap, OnModuleDestroy, Optional } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import type { ScannerType } from '@ctem/contracts';
import {
  LeaderLease,
  RedisClient,
  SCAN_SCHEDULE_LEASE_KEY,
  UnavailableLeaseStore,
  runIfLeader,
  type LeaseStore,
} from '@ctem/coordination';
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

/** Interval between scheduled-scan sweeps. Unchanged by leader election. */
export const SCAN_SCHEDULE_TICK_MS = 5 * 60_000;

@Injectable()
export class ScanScheduleService implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly log = rootLogger.child({ component: 'scan-schedule' });
  private timer?: NodeJS.Timeout;
  private readonly lease: LeaderLease;

  constructor(
    private readonly prisma: PrismaService,
    private readonly dispatcher: ScanDispatcherService,
    @Optional() @Inject(RedisClient) store?: LeaseStore,
  ) {
    this.lease = new LeaderLease(store ?? new UnavailableLeaseStore(), SCAN_SCHEDULE_LEASE_KEY);
  }

  onApplicationBootstrap(): void {
    this.lease.start();
    this.timer = setInterval(() => void this.runScheduledTick(), SCAN_SCHEDULE_TICK_MS);
    this.log.info(
      { intervalMs: SCAN_SCHEDULE_TICK_MS, leaseKey: SCAN_SCHEDULE_LEASE_KEY },
      'scan scheduler started',
    );
  }

  /**
   * Interval entrypoint. Only the Redis lease holder runs {@link tick}.
   * Manual / webhook / CI createScan on the dispatcher is not gated here.
   */
  async runScheduledTick(): Promise<void> {
    await runIfLeader(this.lease, this.log, () => this.tick());
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

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.lease.stop();
  }
}

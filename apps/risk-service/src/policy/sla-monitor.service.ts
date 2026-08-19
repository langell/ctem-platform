import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { EventBus } from '@ctem/events';
import { SUBJECTS } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';

/**
 * Emits an event the first time a finding blows its SLA. Fires once per finding
 * — an alert that repeats every hour is an alert people mute.
 */
@Injectable()
export class SlaMonitorService implements OnApplicationBootstrap {
  private readonly log = rootLogger.child({ component: 'sla-monitor' });
  private timer?: NodeJS.Timeout;
  private readonly notified = new Set<string>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: EventBus,
  ) {}

  onApplicationBootstrap(): void {
    this.timer = setInterval(() => void this.tick(), 10 * 60_000);
  }

  private async tick(): Promise<void> {
    const breached = await this.prisma.unsafeCrossTenant('SLA sweep across all orgs', (db) =>
      db.finding.findMany({
        where: {
          slaDueAt: { lt: new Date() },
          resolvedAt: null,
          state: { in: ['open', 'triaged', 'in_progress'] },
        },
        select: { id: true, orgId: true, slaDueAt: true },
        take: 5_000,
      }),
    );

    for (const finding of breached) {
      // TODO: persist the notified set (Redis or a column) so a restart does not
      // re-alert on every open breach.
      if (this.notified.has(finding.id)) continue;
      this.notified.add(finding.id);
      await this.bus.publish(SUBJECTS.slaBreached, finding.orgId, {
        findingId: finding.id,
        dueAt: finding.slaDueAt!,
      });
    }

    if (breached.length) this.log.info({ count: breached.length }, 'SLA sweep complete');
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }
}

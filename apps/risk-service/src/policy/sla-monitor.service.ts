import { Injectable, OnApplicationBootstrap, OnModuleDestroy } from '@nestjs/common';
import { PrismaService, type PrismaTransaction } from '@ctem/db';
import { EventBus } from '@ctem/events';
import { SUBJECTS } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';

/** Interval between SLA breach sweeps. Notify-once claiming does not change cadence. */
export const SLA_MONITOR_TICK_MS = 10 * 60_000;

const OPEN_SLA_STATES = ['open', 'triaged', 'in_progress'] as const;

export type SlaClaimRow = { id: string; slaDueAt: Date };

/**
 * Atomically claims the first SLA-breach alert for a finding.
 * Wins iff `slaNotifiedAt` is still null and the row is still an open breach.
 * Caller must run this inside `PrismaService.withOrg` (RLS-safe).
 */
export async function claimSlaBreachNotification(
  tx: PrismaTransaction,
  findingId: string,
): Promise<SlaClaimRow | null> {
  const rows = await tx.$queryRaw<SlaClaimRow[]>`
    UPDATE findings
    SET "slaNotifiedAt" = now(), "updatedAt" = now()
    WHERE id = ${findingId}::uuid
      AND "slaNotifiedAt" IS NULL
      AND "resolvedAt" IS NULL
      AND "slaDueAt" IS NOT NULL
      AND "slaDueAt" < now()
      AND state IN ('open', 'triaged', 'in_progress')
    RETURNING id, "slaDueAt"
  `;
  return rows[0] ?? null;
}

/**
 * Emits `ctem.policy.sla_breached` the first time a finding blows its SLA.
 * Notify-once is a durable column claim on `findings.slaNotifiedAt` — not an
 * in-memory Set and not Redis — so it survives restart, replica overlap, and
 * a Redis flush.
 */
@Injectable()
export class SlaMonitorService implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly log = rootLogger.child({ component: 'sla-monitor' });
  private timer?: NodeJS.Timeout;

  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: EventBus,
  ) {}

  onApplicationBootstrap(): void {
    this.timer = setInterval(() => void this.runSweep(), SLA_MONITOR_TICK_MS);
  }

  /**
   * Sweep entrypoint. Lists open breaches, then org-scopes an atomic claim
   * before publish. A lost claim or a claim error skips that finding this tick.
   */
  async runSweep(): Promise<void> {
    const breached = await this.prisma.unsafeCrossTenant('SLA sweep across all orgs', (db) =>
      db.finding.findMany({
        where: {
          slaDueAt: { lt: new Date() },
          resolvedAt: null,
          state: { in: [...OPEN_SLA_STATES] },
          slaNotifiedAt: null,
        },
        select: { id: true, orgId: true, slaDueAt: true },
        take: 5_000,
      }),
    );

    let published = 0;
    for (const finding of breached) {
      try {
        const claimed = await this.prisma.withOrg(finding.orgId, (tx) =>
          claimSlaBreachNotification(tx, finding.id),
        );
        if (!claimed) continue;
        await this.bus.publish(SUBJECTS.slaBreached, finding.orgId, {
          findingId: claimed.id,
          dueAt: claimed.slaDueAt,
        });
        published += 1;
      } catch (err) {
        this.log.error(
          { err, findingId: finding.id, orgId: finding.orgId },
          'SLA claim failed; skipping this finding this tick',
        );
      }
    }

    if (breached.length) this.log.info({ count: breached.length, published }, 'SLA sweep complete');
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }
}

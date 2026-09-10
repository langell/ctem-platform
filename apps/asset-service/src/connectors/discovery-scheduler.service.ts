import { Inject, Injectable, OnApplicationBootstrap, OnModuleDestroy, Optional } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import {
  DISCOVERY_SCHEDULE_LEASE_KEY,
  LeaderLease,
  RedisClient,
  UnavailableLeaseStore,
  runIfLeader,
  type LeaseStore,
} from '@ctem/coordination';
import { AssetsService } from '../assets/assets.service';
import { ConnectorRegistry } from './connector.registry';

/** The shape syncIntegration needs — a structural subset of the Prisma row. */
export interface IntegrationRow {
  id: string;
  orgId: string;
  provider: string;
  config: unknown;
  credentialRef: string | null;
  lastSyncAt: Date | null;
}

export interface SyncResult {
  integrationId: string;
  provider: string;
  upserted: number;
  archived: number;
  error: string | null;
}

/** Interval between discovery sweeps. Unchanged by leader election. */
export const DISCOVERY_SCHEDULE_TICK_MS = 15 * 60_000;

/**
 * Continuous discovery — the "C" in CTEM. Every enabled integration is re-synced
 * on an interval; assets that stop appearing are archived so the inventory
 * reflects reality rather than accumulating ghosts.
 *
 * The interval path is Redis-lease gated so two asset-service replicas do not
 * both sync the same window. {@link syncOrg} / {@link syncIntegration} stay
 * ungated — they are the manual / API kick.
 */
@Injectable()
export class DiscoverySchedulerService implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly log = rootLogger.child({ component: 'discovery' });
  private timer?: NodeJS.Timeout;
  private readonly lease: LeaderLease;

  constructor(
    private readonly prisma: PrismaService,
    private readonly registry: ConnectorRegistry,
    private readonly assets: AssetsService,
    @Optional() @Inject(RedisClient) store?: LeaseStore,
  ) {
    this.lease = new LeaderLease(store ?? new UnavailableLeaseStore(), DISCOVERY_SCHEDULE_LEASE_KEY);
  }

  onApplicationBootstrap(): void {
    this.lease.start();
    this.timer = setInterval(() => void this.runScheduledTick(), DISCOVERY_SCHEDULE_TICK_MS);
    this.log.info(
      { intervalMs: DISCOVERY_SCHEDULE_TICK_MS, leaseKey: DISCOVERY_SCHEDULE_LEASE_KEY },
      'discovery scheduler started',
    );
  }

  /** Interval entrypoint. Only the Redis lease holder runs the sweep. */
  async runScheduledTick(): Promise<void> {
    await runIfLeader(this.lease, this.log, () => this.tick());
  }

  private async tick(): Promise<void> {
    const integrations = await this.prisma.unsafeCrossTenant(
      'discovery scheduler sweeps every org',
      (db) => db.integration.findMany({ where: { enabled: true } }),
    );

    for (const integration of integrations) {
      await this.syncIntegration(integration);
    }
  }

  /** On-demand sweep of one org's integrations — the manual discovery trigger. */
  async syncOrg(orgId: string): Promise<SyncResult[]> {
    const integrations = await this.prisma.withOrg(orgId, (tx) =>
      tx.integration.findMany({ where: { enabled: true } }),
    );
    const results: SyncResult[] = [];
    for (const integration of integrations) {
      results.push(await this.syncIntegration(integration));
    }
    return results;
  }

  async syncIntegration(integration: IntegrationRow): Promise<SyncResult> {
    const base = { integrationId: integration.id, provider: integration.provider };

    const connector = this.registry.get(integration.provider);
    if (!connector) {
      this.log.warn({ provider: integration.provider }, 'no connector registered');
      return { ...base, upserted: 0, archived: 0, error: 'no connector registered' };
    }

    const syncStartedAt = new Date();
    try {
      let upserted = 0;
      for await (const asset of connector.discover({
        orgId: integration.orgId,
        integrationId: integration.id,
        config: integration.config as Record<string, unknown>,
        credentialRef: integration.credentialRef,
        since: integration.lastSyncAt,
      })) {
        await this.assets.upsert(integration.orgId, asset, integration.id);
        upserted += 1;
      }

      const { count: archived } = await this.assets.archiveStale(
        integration.orgId,
        integration.provider,
        syncStartedAt,
        integration.id,
      );
      await this.prisma.withOrg(integration.orgId, (tx) =>
        tx.integration.update({
          where: { id: integration.id },
          data: { lastSyncAt: syncStartedAt, lastSyncError: null },
        }),
      );
      return { ...base, upserted, archived, error: null };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.log.error({ err, integrationId: integration.id }, 'discovery sync failed');
      await this.prisma.withOrg(integration.orgId, (tx) =>
        tx.integration.update({
          where: { id: integration.id },
          data: { lastSyncError: message },
        }),
      );
      return { ...base, upserted: 0, archived: 0, error: message };
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.lease.stop();
  }
}

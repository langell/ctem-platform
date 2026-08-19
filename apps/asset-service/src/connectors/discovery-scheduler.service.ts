import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import { AssetsService } from '../assets/assets.service';
import { ConnectorRegistry } from './connector.registry';

/**
 * Continuous discovery — the "C" in CTEM. Every enabled integration is re-synced
 * on an interval; assets that stop appearing are archived so the inventory
 * reflects reality rather than accumulating ghosts.
 */
@Injectable()
export class DiscoverySchedulerService implements OnApplicationBootstrap {
  private readonly log = rootLogger.child({ component: 'discovery' });
  private timer?: NodeJS.Timeout;

  constructor(
    private readonly prisma: PrismaService,
    private readonly registry: ConnectorRegistry,
    private readonly assets: AssetsService,
  ) {}

  onApplicationBootstrap(): void {
    // TODO: replace the naive interval with a distributed scheduler (leader
    // election or a NATS-backed work queue) before running multiple replicas.
    this.timer = setInterval(() => void this.tick(), 15 * 60_000);
    this.log.info('discovery scheduler started');
  }

  private async tick(): Promise<void> {
    const integrations = await this.prisma.unsafeCrossTenant(
      'discovery scheduler sweeps every org',
      (db) => db.integration.findMany({ where: { enabled: true } }),
    );

    for (const integration of integrations) {
      const connector = this.registry.get(integration.provider);
      if (!connector) {
        this.log.warn({ provider: integration.provider }, 'no connector registered');
        continue;
      }

      const syncStartedAt = new Date();
      try {
        for await (const asset of connector.discover({
          orgId: integration.orgId,
          integrationId: integration.id,
          config: integration.config as Record<string, unknown>,
          credentialRef: integration.credentialRef,
          since: integration.lastSyncAt,
        })) {
          await this.assets.upsert(integration.orgId, asset);
        }

        await this.assets.archiveStale(integration.orgId, integration.provider, syncStartedAt);
        await this.prisma.withOrg(integration.orgId, (tx) =>
          tx.integration.update({
            where: { id: integration.id },
            data: { lastSyncAt: syncStartedAt, lastSyncError: null },
          }),
        );
      } catch (err) {
        this.log.error({ err, integrationId: integration.id }, 'discovery sync failed');
        await this.prisma.withOrg(integration.orgId, (tx) =>
          tx.integration.update({
            where: { id: integration.id },
            data: { lastSyncError: err instanceof Error ? err.message : String(err) },
          }),
        );
      }
    }
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }
}

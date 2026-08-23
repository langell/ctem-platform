import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { EventBus } from '@ctem/events';
import { SUBJECTS, VulnPackagesObservedPayload } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';
import { VulnFeedService } from './vuln-feed.service';

/**
 * Scanners report every package the mirror could not answer; this consumer
 * mirrors them so the next scan is served locally. Intelligence is shared, not
 * tenant-scoped, so the event's org only matters for tracing.
 */
@Injectable()
export class FeedConsumer implements OnApplicationBootstrap {
  private readonly log = rootLogger.child({ component: 'feed-consumer' });

  constructor(
    private readonly bus: EventBus,
    private readonly feed: VulnFeedService,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.bus.subscribe(
      SUBJECTS.vulnPackagesObserved,
      // Mirroring pages through OSV; give it headroom before redelivery.
      { durable: 'risk-vuln-feed', queueGroup: 'risk-vuln-feed', ackWaitMs: 300_000 },
      async (payload) => {
        const { packages } = VulnPackagesObservedPayload.parse(payload);
        const mirrored = await this.feed.mirrorPackages(packages);
        this.log.info({ observed: packages.length, mirrored }, 'observed packages processed');
      },
    );
  }
}

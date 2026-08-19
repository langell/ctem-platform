import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { EventBus } from '@ctem/events';
import { SUBJECTS } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';
import { RiskScoringService } from './risk-scoring.service';
import { PolicyEngineService } from '../policy/policy-engine.service';

/**
 * Score-then-evaluate runs on every new or changed finding. Ordering matters:
 * policies can key off riskScore, so scoring must complete first.
 */
@Injectable()
export class RiskConsumer implements OnApplicationBootstrap {
  private readonly log = rootLogger.child({ component: 'risk-consumer' });

  constructor(
    private readonly bus: EventBus,
    private readonly scoring: RiskScoringService,
    private readonly policy: PolicyEngineService,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    for (const subject of [SUBJECTS.findingCreated, SUBJECTS.findingUpdated] as const) {
      await this.bus.subscribe(
        subject,
        { durable: `risk-${subject.replace(/\./g, '-')}` },
        async (payload, envelope) => {
          const finding = payload as { id: string };
          await this.scoring.score(envelope.orgId, finding.id);
          await this.policy.evaluate(envelope.orgId, finding.id);
        },
      );
    }

    // Feed updates (new EPSS scores, a CVE added to KEV) invalidate every score.
    await this.bus.subscribe(
      SUBJECTS.riskRescoreRequested,
      { durable: 'risk-rescore', ackWaitMs: 300_000 },
      async (payload, envelope) => {
        const { findingIds } = payload as { findingIds: string[] };
        const count = await this.scoring.rescoreAll(envelope.orgId, findingIds);
        this.log.info({ orgId: envelope.orgId, count }, 'rescored findings');
      },
    );
  }
}

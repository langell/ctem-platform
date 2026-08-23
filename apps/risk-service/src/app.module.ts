import { MiddlewareConsumer, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CtemConfigModule } from '@ctem/config';
import { ObservabilityModule, RequestContextMiddleware } from '@ctem/observability';
import { AuthModule, InternalAuthGuard } from '@ctem/auth';
import { EventsModule } from '@ctem/events';
import { DbModule } from '@ctem/db';
import { HealthController } from '@ctem/service-kit';
import { RiskController } from './risk/risk.controller';
import { RiskScoringService } from './risk/risk-scoring.service';
import { PolicyEngineService } from './policy/policy-engine.service';
import { RiskConsumer } from './risk/risk.consumer';
import { SlaMonitorService } from './policy/sla-monitor.service';
import { FeedStore } from './feed/feed.store';
import { VulnFeedService } from './feed/vuln-feed.service';
import { FeedConsumer } from './feed/feed.consumer';

@Module({
  imports: [CtemConfigModule, ObservabilityModule, AuthModule, EventsModule, DbModule],
  controllers: [HealthController, RiskController],
  providers: [
    RiskScoringService,
    PolicyEngineService,
    RiskConsumer,
    SlaMonitorService,
    FeedStore,
    VulnFeedService,
    FeedConsumer,
    { provide: APP_GUARD, useClass: InternalAuthGuard },
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestContextMiddleware).forRoutes('*');
  }
}

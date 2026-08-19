import { MiddlewareConsumer, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CtemConfigModule } from '@ctem/config';
import { ObservabilityModule, RequestContextMiddleware } from '@ctem/observability';
import { AuthModule, InternalAuthGuard } from '@ctem/auth';
import { EventsModule } from '@ctem/events';
import { DbModule } from '@ctem/db';
import { HealthController } from '@ctem/service-kit';
import { FindingsController } from './findings/findings.controller';
import { FindingsService } from './findings/findings.service';
import { FindingIngestConsumer } from './findings/finding-ingest.consumer';
import { FindingNormalizer } from './findings/finding-normalizer';

@Module({
  imports: [CtemConfigModule, ObservabilityModule, AuthModule, EventsModule, DbModule],
  controllers: [HealthController, FindingsController],
  providers: [
    FindingsService,
    FindingNormalizer,
    FindingIngestConsumer,
    { provide: APP_GUARD, useClass: InternalAuthGuard },
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestContextMiddleware).forRoutes('*');
  }
}

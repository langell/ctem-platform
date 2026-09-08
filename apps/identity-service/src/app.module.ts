import { MiddlewareConsumer, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CtemConfigModule } from '@ctem/config';
import { ObservabilityModule, RequestContextMiddleware } from '@ctem/observability';
import { AuthModule, InternalAuthGuard } from '@ctem/auth';
import { EventsModule } from '@ctem/events';
import { DbModule } from '@ctem/db';
import { HealthController } from '@ctem/service-kit';
import { OrgController } from './org/org.controller';
import { AuthResolveController } from './org/auth-resolve.controller';
import { OrgService } from './org/org.service';
import { ApiTokenService } from './tokens/api-token.service';
import { ApiTokenController } from './tokens/api-token.controller';

@Module({
  imports: [CtemConfigModule, ObservabilityModule, AuthModule, EventsModule, DbModule],
  controllers: [HealthController, OrgController, AuthResolveController, ApiTokenController],
  providers: [OrgService, ApiTokenService, { provide: APP_GUARD, useClass: InternalAuthGuard }],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestContextMiddleware).forRoutes('*');
  }
}

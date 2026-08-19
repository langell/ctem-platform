import { MiddlewareConsumer, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CtemConfigModule } from '@ctem/config';
import { ObservabilityModule, RequestContextMiddleware } from '@ctem/observability';
import { AuthModule } from '@ctem/auth';
import { EventsModule } from '@ctem/events';
import { HealthController } from '@ctem/service-kit';
import { GatewayAuthGuard } from './auth/gateway-auth.guard';
import { ServiceProxy } from './proxy/service-proxy';
import { AssetsProxyController } from './routes/assets.controller';
import { ScansProxyController } from './routes/scans.controller';
import { FindingsProxyController } from './routes/findings.controller';
import { RateLimitMiddleware } from './rate-limit.middleware';

/**
 * The gateway is deliberately thin: authenticate, authorize, attach a signed
 * principal, forward. Business logic lives in the domain services so the gateway
 * never becomes the place features go to hide.
 */
@Module({
  imports: [CtemConfigModule, ObservabilityModule, AuthModule, EventsModule],
  controllers: [
    HealthController,
    AssetsProxyController,
    ScansProxyController,
    FindingsProxyController,
  ],
  providers: [ServiceProxy, { provide: APP_GUARD, useClass: GatewayAuthGuard }],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestContextMiddleware, RateLimitMiddleware).forRoutes('*');
  }
}

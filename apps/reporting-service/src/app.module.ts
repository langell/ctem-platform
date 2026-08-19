import { MiddlewareConsumer, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CtemConfigModule } from '@ctem/config';
import { ObservabilityModule, RequestContextMiddleware } from '@ctem/observability';
import { AuthModule, InternalAuthGuard } from '@ctem/auth';
import { EventsModule } from '@ctem/events';
import { StorageModule } from '@ctem/storage';
import { DbModule } from '@ctem/db';
import { HealthController } from '@ctem/service-kit';
import { DashboardController } from './dashboard/dashboard.controller';
import { DashboardService } from './dashboard/dashboard.service';

@Module({
  imports: [
    CtemConfigModule,
    ObservabilityModule,
    AuthModule,
    EventsModule,
    StorageModule,
    DbModule,
  ],
  controllers: [HealthController, DashboardController],
  providers: [DashboardService, { provide: APP_GUARD, useClass: InternalAuthGuard }],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestContextMiddleware).forRoutes('*');
  }
}

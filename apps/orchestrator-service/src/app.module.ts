import { MiddlewareConsumer, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CtemConfigModule } from '@ctem/config';
import { ObservabilityModule, RequestContextMiddleware } from '@ctem/observability';
import { AuthModule, InternalAuthGuard } from '@ctem/auth';
import { EventsModule } from '@ctem/events';
import { StorageModule } from '@ctem/storage';
import { DbModule } from '@ctem/db';
import { HealthController } from '@ctem/service-kit';
import { ScansController } from './scans/scans.controller';
import { ScanPlannerService } from './scans/scan-planner.service';
import { ScanDispatcherService } from './scans/scan-dispatcher.service';
import { ScanLifecycleConsumer } from './scans/scan-lifecycle.consumer';
import { ScanScheduleService } from './scans/scan-schedule.service';

@Module({
  imports: [
    CtemConfigModule,
    ObservabilityModule,
    AuthModule,
    EventsModule,
    StorageModule,
    DbModule,
  ],
  controllers: [HealthController, ScansController],
  providers: [
    ScanPlannerService,
    ScanDispatcherService,
    ScanLifecycleConsumer,
    ScanScheduleService,
    { provide: APP_GUARD, useClass: InternalAuthGuard },
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestContextMiddleware).forRoutes('*');
  }
}

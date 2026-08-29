import { MiddlewareConsumer, Module, OnModuleInit } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CtemConfigModule } from '@ctem/config';
import { ObservabilityModule, RequestContextMiddleware } from '@ctem/observability';
import { AuthModule, InternalAuthGuard } from '@ctem/auth';
import { EventsModule } from '@ctem/events';
import { DbModule } from '@ctem/db';
import { HealthController } from '@ctem/service-kit';
import { AssetsController } from './assets/assets.controller';
import { AssetsService } from './assets/assets.service';
import { AssetGraphService } from './assets/asset-graph.service';
import { ConnectorRegistry } from './connectors/connector.registry';
import { DiscoverySchedulerService } from './connectors/discovery-scheduler.service';
import { GitHubConnector } from './connectors/github.connector';

@Module({
  imports: [CtemConfigModule, ObservabilityModule, AuthModule, EventsModule, DbModule],
  controllers: [HealthController, AssetsController],
  providers: [
    AssetsService,
    AssetGraphService,
    ConnectorRegistry,
    DiscoverySchedulerService,
    GitHubConnector,
    { provide: APP_GUARD, useClass: InternalAuthGuard },
  ],
})
export class AppModule implements OnModuleInit {
  constructor(
    private readonly registry: ConnectorRegistry,
    private readonly github: GitHubConnector,
  ) {}

  /** Connector registration is explicit and lives in one greppable place. */
  onModuleInit(): void {
    this.registry.register(this.github);
  }

  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestContextMiddleware).forRoutes('*');
  }
}

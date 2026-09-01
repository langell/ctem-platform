import { MiddlewareConsumer, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CtemConfigModule } from '@ctem/config';
import { ObservabilityModule, RequestContextMiddleware } from '@ctem/observability';
import { AuthModule, InternalAuthGuard } from '@ctem/auth';
import { EventsModule } from '@ctem/events';
import { DbModule } from '@ctem/db';
import { HealthController } from '@ctem/service-kit';
import { NotificationConsumer } from './notification.consumer';
import { ChannelRegistry } from './channels/channel.registry';
import { SlackChannel } from './channels/slack.channel';
import { WebhookChannel } from './channels/webhook.channel';

@Module({
  imports: [CtemConfigModule, ObservabilityModule, AuthModule, EventsModule, DbModule],
  controllers: [HealthController],
  providers: [
    ChannelRegistry,
    WebhookChannel,
    SlackChannel,
    NotificationConsumer,
    { provide: APP_GUARD, useClass: InternalAuthGuard },
  ],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestContextMiddleware).forRoutes('*');
  }
}

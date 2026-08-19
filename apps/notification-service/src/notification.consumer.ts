import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { EventBus } from '@ctem/events';
import { SUBJECTS } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';
import { ChannelRegistry } from './channels/channel.registry';
import { WebhookChannel } from './channels/webhook.channel';

@Injectable()
export class NotificationConsumer implements OnApplicationBootstrap {
  private readonly log = rootLogger.child({ component: 'notifications' });

  constructor(
    private readonly bus: EventBus,
    private readonly registry: ChannelRegistry,
    private readonly webhook: WebhookChannel,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    this.registry.register(this.webhook);

    await this.bus.subscribe(
      SUBJECTS.notificationRequested,
      { durable: 'notification-dispatch', maxDeliver: 6 },
      async (payload, envelope) => {
        const message = payload as {
          channel: string;
          template: string;
          target: string;
          data: Record<string, unknown>;
        };
        const channel = this.registry.get(message.channel);
        if (!channel) {
          this.log.warn({ channel: message.channel }, 'no channel registered, dropping');
          return;
        }
        await channel.send({
          orgId: envelope.orgId,
          template: message.template,
          target: message.target,
          data: message.data,
        });
      },
    );

    // Policy hits and SLA breaches become notifications; routing (which team,
    // which channel) is resolved from asset ownership.
    await this.bus.subscribe(
      SUBJECTS.policyViolated,
      { durable: 'notification-policy' },
      async (payload, envelope) => {
        this.log.info({ orgId: envelope.orgId, payload }, 'policy violation received');
        // TODO: resolve owner -> channel, render the template, then publish
        // notificationRequested so delivery retries independently of routing.
      },
    );
  }
}

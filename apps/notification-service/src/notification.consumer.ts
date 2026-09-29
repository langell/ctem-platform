import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { EventBus } from '@ctem/events';
import { SUBJECTS } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';
import { ChannelRegistry } from './channels/channel.registry';
import { JiraChannel } from './channels/jira.channel';
import { SlackChannel } from './channels/slack.channel';
import { WebhookChannel } from './channels/webhook.channel';
import { PrismaPolicyDeliveryClaims, sendWithDeliveryClaim } from './delivery-claim';
import { dispatchPolicyViolated } from './policy-notify';

@Injectable()
export class NotificationConsumer implements OnApplicationBootstrap {
  private readonly log = rootLogger.child({ component: 'notifications' });

  constructor(
    private readonly bus: EventBus,
    private readonly registry: ChannelRegistry,
    private readonly webhook: WebhookChannel,
    private readonly slack: SlackChannel,
    private readonly jira: JiraChannel,
    private readonly claims: PrismaPolicyDeliveryClaims,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    this.registry.register(this.webhook);
    this.registry.register(this.slack);
    this.registry.register(this.jira);

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
        const data = message.data ?? {};
        // Org is the envelope only. data.orgId and tenant host fields are not a claim key.
        const outcome = await sendWithDeliveryClaim(
          {
            orgId: envelope.orgId,
            channel: message.channel,
            template: message.template,
            target: message.target,
            data,
          },
          () =>
            channel.send({
              orgId: envelope.orgId,
              template: message.template,
              target: message.target,
              data,
            }),
          this.claims,
        );
        if (outcome === 'skipped') {
          this.log.info(
            { orgId: envelope.orgId, channel: message.channel, template: message.template },
            'policy delivery already claimed; skipping send',
          );
        }
      },
    );

    // Policy hits enqueue one notification per channel. HTTP stays on
    // notification-dispatch (env:SLACK_* / env:JIRA_* — not tenant config,
    // body, query, or message.target). CORS and unknown query forwarding
    // stay comments.
    await this.bus.subscribe(
      SUBJECTS.policyViolated,
      { durable: 'notification-policy' },
      async (payload, envelope) => {
        const notice = payload as {
          findingId: string;
          policyId: string;
          actions: string[];
        };
        this.log.info({ orgId: envelope.orgId, payload: notice }, 'policy violation received');
        await dispatchPolicyViolated(envelope.orgId, notice, this.bus, {
          causationId: envelope.causationId,
        });
      },
    );
  }
}

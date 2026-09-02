import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { EventBus } from '@ctem/events';
import { SUBJECTS } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';
import { ChannelRegistry } from './channels/channel.registry';
import { JiraChannel } from './channels/jira.channel';
import { SlackChannel } from './channels/slack.channel';
import { WebhookChannel } from './channels/webhook.channel';
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
        await channel.send({
          orgId: envelope.orgId,
          template: message.template,
          target: message.target,
          data: message.data,
        });
      },
    );

    // Policy hits become Slack on notify and Jira on ticket. Hosts are
    // platform env:SLACK_* / env:JIRA_* — not tenant config/body/query,
    // not message.target. CORS / PAT / query-forwarding stay comments.
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
        await dispatchPolicyViolated(envelope.orgId, notice, { slack: this.slack, jira: this.jira });
      },
    );
  }
}

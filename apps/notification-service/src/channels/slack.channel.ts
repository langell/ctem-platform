import { Injectable } from '@nestjs/common';
import { rootLogger } from '@ctem/observability';
import type { NotificationChannel, NotificationMessage } from './channel.registry';
import {
  PLATFORM_SLACK_CREDENTIAL_REF,
  requireSlackWebhookCredential,
} from './credentials';
import { allowlistedSlackWebhookUrl, tenantSuppliedWebhookUrls } from './slack.egress';

/**
 * Slack incoming webhook. The hook URL is platform-operated `env:SLACK_*`
 * only — never `message.target`, tenant config, body, or query.
 */
@Injectable()
export class SlackChannel implements NotificationChannel {
  readonly name = 'slack';
  private readonly log = rootLogger.child({ component: 'slack-channel' });

  async send(message: NotificationMessage): Promise<void> {
    const ignored = tenantSuppliedWebhookUrls(message);
    if (ignored.length) {
      this.log.warn(
        { count: ignored.length },
        'ignoring tenant-supplied webhook URL — Slack egress is env:SLACK_* only',
      );
    }

    const url = allowlistedSlackWebhookUrl(requireSlackWebhookCredential(PLATFORM_SLACK_CREDENTIAL_REF));
    const body = JSON.stringify(slackPayload(message));

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      throw new Error(`Slack webhook responded ${res.status}`);
    }
    this.log.info({ template: message.template, orgId: message.orgId }, 'slack delivered');
  }
}

export function slackPayload(message: NotificationMessage): { text: string } {
  const findingId = typeof message.data.findingId === 'string' ? message.data.findingId : 'unknown';
  const policyId = typeof message.data.policyId === 'string' ? message.data.policyId : 'unknown';
  const actions = Array.isArray(message.data.actions) ? message.data.actions.join(', ') : 'notify';
  return {
    text: `CTEM policy violated — org ${message.orgId} finding ${findingId} policy ${policyId} actions [${actions}]`,
  };
}

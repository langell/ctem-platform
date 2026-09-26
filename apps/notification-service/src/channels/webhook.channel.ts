import { Injectable, Optional } from '@nestjs/common';
import { createHmac } from 'node:crypto';
import { rootLogger } from '@ctem/observability';
import { InternalHttpPolicy } from '@ctem/resilience';
import type { NotificationChannel, NotificationMessage } from './channel.registry';
import { createNotificationEgressPolicy } from './notification-egress';

/**
 * One breaker for every tenant webhook target. Not per URL and not per org.
 */
export const EGRESS_TENANT_WEBHOOK = 'egress:tenant-webhook';

/**
 * Generic outbound webhook. Payloads are HMAC-signed so receivers can verify
 * the call came from us, the same way GitHub signs its webhooks.
 *
 * The POST keeps its 10s timeout and HMAC signature. Attempts are 1 (no
 * in-policy retry). An open circuit or a failed send throws so JetStream
 * `notification-dispatch` naks and redelivers.
 */
@Injectable()
export class WebhookChannel implements NotificationChannel {
  readonly name = 'webhook';
  private readonly log = rootLogger.child({ component: 'webhook-channel' });
  private readonly policy: InternalHttpPolicy;

  constructor(@Optional() policy?: InternalHttpPolicy) {
    this.policy = policy ?? createNotificationEgressPolicy();
  }

  async send(message: NotificationMessage): Promise<void> {
    const body = JSON.stringify({
      template: message.template,
      orgId: message.orgId,
      data: message.data,
      sentAt: new Date().toISOString(),
    });

    // TODO: per-integration signing secret from the secret store.
    const signature = createHmac('sha256', 'dev-webhook-secret').update(body).digest('hex');

    const res = await this.policy.execute(EGRESS_TENANT_WEBHOOK, (_signal) =>
      fetch(message.target, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-ctem-signature': `sha256=${signature}`,
        },
        body,
        signal: AbortSignal.timeout(10_000),
      }),
    );

    if (!res.ok) {
      // Throwing nak's the message; JetStream retries with backoff.
      throw new Error(`Webhook ${message.target} responded ${res.status}`);
    }
    this.log.info({ target: message.target, template: message.template }, 'webhook delivered');
  }
}

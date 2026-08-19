import { Injectable } from '@nestjs/common';
import { createHmac } from 'node:crypto';
import { rootLogger } from '@ctem/observability';
import type { NotificationChannel, NotificationMessage } from './channel.registry';

/**
 * Generic outbound webhook. Payloads are HMAC-signed so receivers can verify
 * the call came from us, the same way GitHub signs its webhooks.
 */
@Injectable()
export class WebhookChannel implements NotificationChannel {
  readonly name = 'webhook';
  private readonly log = rootLogger.child({ component: 'webhook-channel' });

  async send(message: NotificationMessage): Promise<void> {
    const body = JSON.stringify({
      template: message.template,
      orgId: message.orgId,
      data: message.data,
      sentAt: new Date().toISOString(),
    });

    // TODO: per-integration signing secret from the secret store.
    const signature = createHmac('sha256', 'dev-webhook-secret').update(body).digest('hex');

    const res = await fetch(message.target, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-ctem-signature': `sha256=${signature}`,
      },
      body,
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      // Throwing nak's the message; JetStream retries with backoff.
      throw new Error(`Webhook ${message.target} responded ${res.status}`);
    }
    this.log.info({ target: message.target, template: message.template }, 'webhook delivered');
  }
}

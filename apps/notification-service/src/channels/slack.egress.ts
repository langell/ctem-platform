/**
 * Slack incoming-webhook egress allowlist. Only `https://hooks.slack.com/services/…`
 * is permitted. A tenant-writable host (or any other Slack API host) must never
 * become the POST target.
 */

export const SLACK_WEBHOOK_HOST = 'hooks.slack.com';

export class SlackEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SlackEgressError';
  }
}

const SERVICE_SEGMENT = /^[A-Za-z0-9_-]+$/;

/** True when a string looks like an absolute URL a tenant might try to inject. */
export function looksLikeAbsoluteUrl(value: string): boolean {
  return /^https?:\/\//i.test(value.trim());
}

/**
 * Canonicalize and allowlist a Slack incoming-webhook URL. Throws rather than
 * returning a host we must not POST to.
 */
export function allowlistedSlackWebhookUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new SlackEgressError(`Refusing unparseable Slack webhook URL`);
  }
  if (parsed.protocol !== 'https:') {
    throw new SlackEgressError(`Refusing non-https Slack webhook URL — only https://${SLACK_WEBHOOK_HOST} is permitted`);
  }
  if (parsed.hostname !== SLACK_WEBHOOK_HOST) {
    throw new SlackEgressError(
      `Refusing Slack webhook host '${parsed.hostname}' — only ${SLACK_WEBHOOK_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new SlackEgressError(`Refusing Slack webhook URL with a non-default port`);
  }
  if (parsed.username || parsed.password) {
    throw new SlackEgressError('Refusing Slack webhook URL that embeds userinfo');
  }
  const parts = parsed.pathname.split('/').filter(Boolean);
  if (parts[0] !== 'services' || parts.length < 4 || !parts.every((p) => SERVICE_SEGMENT.test(p))) {
    throw new SlackEgressError('Refusing Slack webhook URL with an unexpected path');
  }
  return `https://${SLACK_WEBHOOK_HOST}/${parts.join('/')}`;
}

/**
 * Tenant-writable fields on the notification message (target, data.webhookUrl,
 * body/query-shaped keys) must never choose the egress host.
 */
export function tenantSuppliedWebhookUrls(input: {
  target?: string;
  data?: Record<string, unknown>;
}): string[] {
  const found: string[] = [];
  const consider = (value: unknown) => {
    if (typeof value === 'string' && looksLikeAbsoluteUrl(value)) found.push(value);
  };
  consider(input.target);
  const data = input.data ?? {};
  for (const key of ['webhookUrl', 'webhook', 'url', 'target', 'hookUrl', 'slackWebhook']) {
    consider(data[key]);
  }
  return found;
}

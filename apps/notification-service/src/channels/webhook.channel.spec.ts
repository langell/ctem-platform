import { createHmac } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CircuitOpenError,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  InternalHttpPolicy,
  type CircuitBreakerConfig,
} from '@ctem/resilience';
import type { NotificationMessage } from './channel.registry';
import { EGRESS_JIRA_API, JiraChannel } from './jira.channel';
import { createNotificationEgressPolicy } from './notification-egress';
import { EGRESS_SLACK_WEBHOOK, SlackChannel } from './slack.channel';
import { EGRESS_TENANT_WEBHOOK, WebhookChannel } from './webhook.channel';

const TARGET_A = 'https://a.example/hooks/ctem';
const TARGET_B = 'https://b.example/hooks/ctem';
const HOOK = 'https://hooks.slack.com/services/TEST/HOOK/dummy';
const SITE = 'https://acme.atlassian.net';
const ISSUE_URL = `${SITE}/rest/api/3/issue`;

const orgId = '11111111-1111-4111-8111-111111111111';
const otherOrgId = '22222222-2222-4222-8222-222222222222';
const findingId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const policyId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

function message(over: Partial<NotificationMessage> = {}): NotificationMessage {
  return {
    orgId,
    template: 'policy.violated',
    target: TARGET_A,
    data: { findingId, policyId, actions: ['notify'] },
    ...over,
  };
}

function setJiraEnv() {
  process.env.JIRA_API_TOKEN = 'jira-token';
  process.env.JIRA_EMAIL = 'sec@example.com';
  process.env.JIRA_BASE_URL = SITE;
  process.env.JIRA_PROJECT_KEY = 'SEC';
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.SLACK_WEBHOOK_URL;
  delete process.env.JIRA_API_TOKEN;
  delete process.env.JIRA_EMAIL;
  delete process.env.JIRA_BASE_URL;
  delete process.env.JIRA_PROJECT_KEY;
  delete process.env.JIRA_ISSUE_TYPE;
});

function stubFetch(status = 200): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async () => new Response('ok', { status }));
  vi.stubGlobal('fetch', fn);
  return fn;
}

function fastPolicy(
  overrides: Partial<CircuitBreakerConfig> = {},
  deps: { now?: () => number } = {},
): InternalHttpPolicy {
  return new InternalHttpPolicy(
    {
      ...DEFAULT_CIRCUIT_BREAKER_CONFIG,
      failureThreshold: 2,
      windowMs: 10_000,
      cooldownMs: 1_000,
      maxAttempts: 1,
      baseDelayMs: 1,
      timeoutMs: 10_000,
      ...overrides,
    },
    { sleep: async () => undefined, random: () => 0, ...deps },
  );
}

describe('WebhookChannel.send', () => {
  it('POSTs the HMAC-signed payload to the tenant target with a 10s timeout', async () => {
    const timeout = vi.spyOn(AbortSignal, 'timeout');
    const fetchFn = stubFetch();
    try {
      await new WebhookChannel().send(message());
      expect(fetchFn).toHaveBeenCalledTimes(1);
      const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(TARGET_A);
      expect(init.method).toBe('POST');
      const body = String(init.body);
      const parsed = JSON.parse(body) as {
        template: string;
        orgId: string;
        data: Record<string, unknown>;
        sentAt: string;
      };
      expect(parsed.template).toBe('policy.violated');
      expect(parsed.orgId).toBe(orgId);
      expect(parsed.data).toEqual({ findingId, policyId, actions: ['notify'] });
      expect(parsed.sentAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      const signature = createHmac('sha256', 'dev-webhook-secret').update(body).digest('hex');
      expect(init.headers).toEqual({
        'content-type': 'application/json',
        'x-ctem-signature': `sha256=${signature}`,
      });
      expect(timeout.mock.calls.at(-1)?.[0]).toBe(10_000);
      expect(init.signal).toBe(timeout.mock.results.at(-1)?.value);
    } finally {
      timeout.mockRestore();
    }
  });

  it('calls fetch once on a 503 and then throws (no in-policy retry)', async () => {
    const fetchFn = stubFetch(503);
    await expect(new WebhookChannel().send(message())).rejects.toThrow(
      `Webhook ${TARGET_A} responded 503`,
    );
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('keeps a single attempt when CTEM_CB_MAX_ATTEMPTS is higher', async () => {
    const fetchFn = stubFetch(503);
    const channel = new WebhookChannel(
      createNotificationEgressPolicy({ CTEM_CB_MAX_ATTEMPTS: '8', CTEM_CB_BASE_DELAY_MS: '1' }),
    );
    await expect(channel.send(message())).rejects.toThrow(`Webhook ${TARGET_A} responded 503`);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('throws on an open circuit without calling fetch, for any tenant target', async () => {
    const channel = new WebhookChannel(fastPolicy({ failureThreshold: 1 }));
    const fetchFn = stubFetch(503);
    await expect(channel.send(message({ target: TARGET_A }))).rejects.toThrow(
      `Webhook ${TARGET_A} responded 503`,
    );
    expect(fetchFn).toHaveBeenCalledTimes(1);
    fetchFn.mockClear();
    await expect(channel.send(message({ target: TARGET_B, orgId: otherOrgId }))).rejects.toMatchObject({
      name: 'CircuitOpenError',
      circuit: EGRESS_TENANT_WEBHOOK,
    });
    await expect(channel.send(message({ target: TARGET_B, orgId: otherOrgId }))).rejects.toBeInstanceOf(
      CircuitOpenError,
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('closes the circuit after a successful half-open probe', async () => {
    let now = 0;
    const channel = new WebhookChannel(
      fastPolicy({ failureThreshold: 2, cooldownMs: 100 }, { now: () => now }),
    );
    const fetchFn = stubFetch(503);
    await expect(channel.send(message())).rejects.toThrow(`Webhook ${TARGET_A} responded 503`);
    await expect(channel.send(message())).rejects.toThrow(`Webhook ${TARGET_A} responded 503`);
    fetchFn.mockClear();
    await expect(channel.send(message())).rejects.toBeInstanceOf(CircuitOpenError);
    expect(fetchFn).not.toHaveBeenCalled();

    now += 100;
    fetchFn.mockResolvedValue(new Response('ok', { status: 200 }));
    await channel.send(message());
    expect(fetchFn).toHaveBeenCalledTimes(1);

    fetchFn.mockClear();
    fetchFn.mockResolvedValue(new Response('unavailable', { status: 503 }));
    await expect(channel.send(message())).rejects.toThrow(`Webhook ${TARGET_A} responded 503`);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    fetchFn.mockClear();
    fetchFn.mockResolvedValue(new Response('ok', { status: 200 }));
    await channel.send(message());
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('opens egress:tenant-webhook without opening slack or jira', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    setJiraEnv();
    const policy = fastPolicy({ failureThreshold: 1 });
    const webhook = new WebhookChannel(policy);
    const slack = new SlackChannel(policy);
    const jira = new JiraChannel(policy);
    const fetchFn = stubFetch(503);
    await expect(webhook.send(message())).rejects.toThrow(`Webhook ${TARGET_A} responded 503`);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    fetchFn.mockClear();
    await expect(webhook.send(message({ target: TARGET_B }))).rejects.toMatchObject({
      name: 'CircuitOpenError',
      circuit: EGRESS_TENANT_WEBHOOK,
    });
    expect(fetchFn).not.toHaveBeenCalled();

    fetchFn.mockResolvedValue(new Response('ok', { status: 200 }));
    await slack.send({
      orgId,
      template: 'policy.violated',
      target: 'slack',
      data: { findingId, policyId, actions: ['notify'] },
    });
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0][0]).toBe(HOOK);

    fetchFn.mockResolvedValue(new Response(JSON.stringify({ key: 'SEC-1' }), { status: 201 }));
    await jira.send({
      orgId,
      template: 'policy.violated',
      target: 'jira',
      data: { findingId, policyId, actions: ['ticket'] },
    });
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(fetchFn.mock.calls[1][0]).toBe(ISSUE_URL);
  });

  it('leaves egress:tenant-webhook closed when slack or jira is open', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    setJiraEnv();
    const policy = fastPolicy({ failureThreshold: 1 });
    const webhook = new WebhookChannel(policy);
    const slack = new SlackChannel(policy);
    const jira = new JiraChannel(policy);
    const fetchFn = vi.fn(async (url: string) => {
      if (url === HOOK || url === ISSUE_URL) return new Response('unavailable', { status: 503 });
      return new Response('ok', { status: 200 });
    });
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      slack.send({
        orgId,
        template: 'policy.violated',
        target: 'slack',
        data: { findingId, policyId, actions: ['notify'] },
      }),
    ).rejects.toThrow(/responded 503/);
    fetchFn.mockClear();
    await expect(
      slack.send({
        orgId,
        template: 'policy.violated',
        target: 'slack',
        data: {},
      }),
    ).rejects.toMatchObject({ name: 'CircuitOpenError', circuit: EGRESS_SLACK_WEBHOOK });
    expect(fetchFn).not.toHaveBeenCalled();

    await webhook.send(message({ target: TARGET_A }));
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0][0]).toBe(TARGET_A);

    fetchFn.mockClear();
    await expect(
      jira.send({
        orgId,
        template: 'policy.violated',
        target: 'jira',
        data: { findingId, policyId, actions: ['ticket'] },
      }),
    ).rejects.toThrow(/responded 503/);
    fetchFn.mockClear();
    await expect(
      jira.send({
        orgId,
        template: 'policy.violated',
        target: 'jira',
        data: {},
      }),
    ).rejects.toMatchObject({ name: 'CircuitOpenError', circuit: EGRESS_JIRA_API });
    expect(fetchFn).not.toHaveBeenCalled();

    await webhook.send(message({ target: TARGET_B, orgId: otherOrgId }));
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0][0]).toBe(TARGET_B);
  });
});

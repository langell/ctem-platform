import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CircuitOpenError,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  InternalHttpPolicy,
  type CircuitBreakerConfig,
} from '@ctem/resilience';
import {
  EGRESS_SLACK_WEBHOOK,
  SlackChannel,
  createNotificationEgressPolicy,
  slackPayload,
} from './slack.channel';
import type { NotificationMessage } from './channel.registry';

const HOOK = 'https://hooks.slack.com/services/TEST/HOOK/dummy';
const TENANT_HOOK = 'https://evil.example/hooks/steal';

const orgId = '11111111-1111-4111-8111-111111111111';
const findingId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const policyId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

function message(over: Partial<NotificationMessage> = {}): NotificationMessage {
  return {
    orgId,
    template: 'policy.violated',
    target: 'slack',
    data: { findingId, policyId, actions: ['notify'] },
    ...over,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.SLACK_WEBHOOK_URL;
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

describe('SlackChannel.send', () => {
  it('POSTs the incoming-webhook payload to the allowlisted env:SLACK_* URL', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const timeout = vi.spyOn(AbortSignal, 'timeout');
    const fetchFn = stubFetch();
    try {
      await new SlackChannel().send(message());
      expect(fetchFn).toHaveBeenCalledTimes(1);
      const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(HOOK);
      expect(init.method).toBe('POST');
      expect(init.headers).toEqual({ 'content-type': 'application/json' });
      expect(JSON.parse(String(init.body))).toEqual(slackPayload(message()));
      expect(timeout.mock.calls.at(-1)?.[0]).toBe(10_000);
      expect(init.signal).toBe(timeout.mock.results.at(-1)?.value);
    } finally {
      timeout.mockRestore();
    }
  });

  it('fails closed when SLACK_WEBHOOK_URL is missing and never POSTs', async () => {
    const fetchFn = stubFetch();
    await expect(new SlackChannel().send(message())).rejects.toThrow(/fails closed/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses a non-hooks.slack.com platform URL and never POSTs', async () => {
    process.env.SLACK_WEBHOOK_URL = 'https://evil.example/hooks/slack';
    const fetchFn = stubFetch();
    await expect(new SlackChannel().send(message())).rejects.toThrow(/only hooks\.slack\.com/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('ignores a tenant-supplied webhook and still POSTs only to hooks.slack.com', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const fetchFn = stubFetch();
    await new SlackChannel().send(
      message({
        target: TENANT_HOOK,
        data: {
          findingId,
          policyId,
          actions: ['notify'],
          webhookUrl: TENANT_HOOK,
          url: 'https://attacker.test/hook',
        },
      }),
    );
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0][0]).toBe(HOOK);
    expect(String(fetchFn.mock.calls[0][0])).not.toContain('evil.example');
  });

  it('does not fall back to a tenant URL when the platform secret is missing', async () => {
    const fetchFn = stubFetch();
    await expect(
      new SlackChannel().send(message({ target: TENANT_HOOK, data: { webhookUrl: TENANT_HOOK } })),
    ).rejects.toThrow(/fails closed/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('naks delivery when Slack responds non-OK', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    stubFetch(500);
    await expect(new SlackChannel().send(message())).rejects.toThrow(/responded 500/);
  });

  it('calls fetch once on a 503 and then throws (no in-policy retry)', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const fetchFn = stubFetch(503);
    await expect(new SlackChannel().send(message())).rejects.toThrow(/responded 503/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('keeps a single attempt when CTEM_CB_MAX_ATTEMPTS is higher', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const fetchFn = stubFetch(503);
    const channel = new SlackChannel(
      createNotificationEgressPolicy({ CTEM_CB_MAX_ATTEMPTS: '3', CTEM_CB_BASE_DELAY_MS: '1' }),
    );
    await expect(channel.send(message())).rejects.toThrow(/responded 503/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('throws on an open circuit without calling fetch', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const channel = new SlackChannel(fastPolicy({ failureThreshold: 1 }));
    const fetchFn = stubFetch(503);
    await expect(channel.send(message())).rejects.toThrow(/responded 503/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    fetchFn.mockClear();
    await expect(channel.send(message())).rejects.toMatchObject({
      name: 'CircuitOpenError',
      circuit: EGRESS_SLACK_WEBHOOK,
    });
    await expect(channel.send(message())).rejects.toBeInstanceOf(CircuitOpenError);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('closes the circuit after a successful half-open probe', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    let now = 0;
    const channel = new SlackChannel(
      fastPolicy({ failureThreshold: 2, cooldownMs: 100 }, { now: () => now }),
    );
    const fetchFn = stubFetch(503);
    await expect(channel.send(message())).rejects.toThrow(/responded 503/);
    await expect(channel.send(message())).rejects.toThrow(/responded 503/);
    fetchFn.mockClear();
    await expect(channel.send(message())).rejects.toBeInstanceOf(CircuitOpenError);
    expect(fetchFn).not.toHaveBeenCalled();

    now += 100;
    fetchFn.mockResolvedValue(new Response('ok', { status: 200 }));
    await channel.send(message());
    expect(fetchFn).toHaveBeenCalledTimes(1);

    fetchFn.mockClear();
    fetchFn.mockResolvedValue(new Response('unavailable', { status: 503 }));
    await expect(channel.send(message())).rejects.toThrow(/responded 503/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    fetchFn.mockClear();
    fetchFn.mockResolvedValue(new Response('ok', { status: 200 }));
    await channel.send(message());
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('still throws on 4xx and does not open the circuit', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const channel = new SlackChannel(fastPolicy({ failureThreshold: 1 }));
    const fetchFn = stubFetch(400);
    await expect(channel.send(message())).rejects.toThrow(/responded 400/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    fetchFn.mockResolvedValue(new Response('ok', { status: 200 }));
    await channel.send(message());
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('does not count an allowlist refusal toward the circuit', async () => {
    const channel = new SlackChannel(fastPolicy({ failureThreshold: 1 }));
    const fetchFn = stubFetch();
    process.env.SLACK_WEBHOOK_URL = 'https://user:pass@hooks.slack.com/services/TEST/HOOK/dummy';
    await expect(channel.send(message())).rejects.toThrow(/userinfo/);
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com:8443/services/TEST/HOOK/dummy';
    await expect(channel.send(message())).rejects.toThrow(/port/);
    process.env.SLACK_WEBHOOK_URL = 'https://evil.example/hooks/slack';
    await expect(channel.send(message())).rejects.toThrow(/only hooks\.slack\.com/);
    expect(fetchFn).not.toHaveBeenCalled();
    process.env.SLACK_WEBHOOK_URL = HOOK;
    await channel.send(message());
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });
});

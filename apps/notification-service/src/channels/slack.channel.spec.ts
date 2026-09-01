import { afterEach, describe, expect, it, vi } from 'vitest';
import { SlackChannel, slackPayload } from './slack.channel';
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

describe('SlackChannel.send', () => {
  it('POSTs the incoming-webhook payload to the allowlisted env:SLACK_* URL', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const fetchFn = stubFetch();
    await new SlackChannel().send(message());
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(HOOK);
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual({ 'content-type': 'application/json' });
    expect(JSON.parse(String(init.body))).toEqual(slackPayload(message()));
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
});

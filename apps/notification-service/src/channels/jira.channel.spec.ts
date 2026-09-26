import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CircuitOpenError,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  InternalHttpPolicy,
  type CircuitBreakerConfig,
} from '@ctem/resilience';
import { JiraChannel, EGRESS_JIRA_API, jiraBasicAuth, jiraIssuePayload } from './jira.channel';
import { createNotificationEgressPolicy } from './notification-egress';
import { SlackChannel } from './slack.channel';
import type { NotificationMessage } from './channel.registry';

const SITE = 'https://acme.atlassian.net';
const ISSUE_URL = `${SITE}/rest/api/3/issue`;
const TENANT_JIRA = 'https://evil.example/rest/api/3/issue';

const orgId = '11111111-1111-4111-8111-111111111111';
const findingId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const policyId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

function message(over: Partial<NotificationMessage> = {}): NotificationMessage {
  return {
    orgId,
    template: 'policy.violated',
    target: 'jira',
    data: { findingId, policyId, actions: ['ticket'] },
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
  delete process.env.JIRA_API_TOKEN;
  delete process.env.JIRA_EMAIL;
  delete process.env.JIRA_BASE_URL;
  delete process.env.JIRA_PROJECT_KEY;
  delete process.env.JIRA_ISSUE_TYPE;
  delete process.env.SLACK_WEBHOOK_URL;
});

function fastPolicy(overrides: Partial<CircuitBreakerConfig> = {}): InternalHttpPolicy {
  return new InternalHttpPolicy(
    {
      ...DEFAULT_CIRCUIT_BREAKER_CONFIG,
      failureThreshold: 1,
      windowMs: 60_000,
      cooldownMs: 60_000,
      maxAttempts: 1,
      baseDelayMs: 1,
      timeoutMs: 10_000,
      ...overrides,
    },
    { sleep: async () => undefined, random: () => 0 },
  );
}

function stubFetch(status = 201): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async () => new Response(JSON.stringify({ key: 'SEC-1' }), { status }));
  vi.stubGlobal('fetch', fn);
  return fn;
}

describe('JiraChannel.send', () => {
  it('POSTs the create-issue payload to the allowlisted Atlassian host', async () => {
    setJiraEnv();
    const fetchFn = stubFetch();
    await new JiraChannel().send(message());
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(ISSUE_URL);
    expect(new URL(url).hostname).toBe('acme.atlassian.net');
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual({
      accept: 'application/json',
      'content-type': 'application/json',
      authorization: jiraBasicAuth('sec@example.com', 'jira-token'),
    });
    expect(JSON.parse(String(init.body))).toEqual(jiraIssuePayload(message(), 'SEC', 'Task'));
  });

  it('fails closed when JIRA_* is missing and never POSTs', async () => {
    const fetchFn = stubFetch();
    await expect(new JiraChannel().send(message())).rejects.toThrow(/fails closed/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses a non-atlassian.net platform URL and never POSTs', async () => {
    setJiraEnv();
    process.env.JIRA_BASE_URL = 'https://evil.example/jira';
    const fetchFn = stubFetch();
    await expect(new JiraChannel().send(message())).rejects.toThrow(/only atlassian\.net/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('ignores a tenant-supplied Jira URL and still POSTs only to atlassian.net', async () => {
    setJiraEnv();
    const fetchFn = stubFetch();
    await new JiraChannel().send(
      message({
        target: TENANT_JIRA,
        data: {
          findingId,
          policyId,
          actions: ['ticket'],
          jiraUrl: TENANT_JIRA,
          url: 'https://attacker.test/jira',
        },
      }),
    );
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0][0]).toBe(ISSUE_URL);
    expect(String(fetchFn.mock.calls[0][0])).not.toContain('evil.example');
  });

  it('does not fall back to a tenant URL when the platform secret is missing', async () => {
    const fetchFn = stubFetch();
    await expect(
      new JiraChannel().send(message({ target: TENANT_JIRA, data: { jiraUrl: TENANT_JIRA } })),
    ).rejects.toThrow(/fails closed/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('naks delivery when Jira responds non-OK', async () => {
    setJiraEnv();
    stubFetch(500);
    await expect(new JiraChannel().send(message())).rejects.toThrow(/responded 500/);
  });

  it('calls fetch once on a 503 and then throws (no second issue create)', async () => {
    setJiraEnv();
    const fetchFn = stubFetch(503);
    await expect(new JiraChannel().send(message())).rejects.toThrow(/responded 503/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('keeps a single attempt when CTEM_CB_MAX_ATTEMPTS is higher', async () => {
    setJiraEnv();
    const fetchFn = stubFetch(503);
    const channel = new JiraChannel(
      createNotificationEgressPolicy({ CTEM_CB_MAX_ATTEMPTS: '8', CTEM_CB_BASE_DELAY_MS: '1' }),
    );
    await expect(channel.send(message())).rejects.toThrow(/responded 503/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('throws on an open circuit without calling fetch', async () => {
    setJiraEnv();
    const channel = new JiraChannel(fastPolicy());
    const fetchFn = stubFetch(503);
    await expect(channel.send(message())).rejects.toThrow(/responded 503/);
    fetchFn.mockClear();
    await expect(channel.send(message())).rejects.toMatchObject({
      name: 'CircuitOpenError',
      circuit: EGRESS_JIRA_API,
    });
    await expect(channel.send(message())).rejects.toBeInstanceOf(CircuitOpenError);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('still throws on 4xx and does not open the circuit', async () => {
    setJiraEnv();
    const channel = new JiraChannel(fastPolicy());
    const fetchFn = stubFetch(400);
    await expect(channel.send(message())).rejects.toThrow(/responded 400/);
    fetchFn.mockResolvedValue(new Response(JSON.stringify({ key: 'SEC-1' }), { status: 201 }));
    await channel.send(message());
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('does not count an allowlist refusal toward the circuit', async () => {
    setJiraEnv();
    const channel = new JiraChannel(fastPolicy());
    const fetchFn = stubFetch();
    process.env.JIRA_BASE_URL = 'https://user:pass@acme.atlassian.net';
    await expect(channel.send(message())).rejects.toThrow(/userinfo/);
    process.env.JIRA_BASE_URL = 'https://acme.atlassian.net:8443';
    await expect(channel.send(message())).rejects.toThrow(/port/);
    process.env.JIRA_BASE_URL = 'https://evil.example/jira';
    await expect(channel.send(message())).rejects.toThrow(/only atlassian\.net/);
    expect(fetchFn).not.toHaveBeenCalled();
    process.env.JIRA_BASE_URL = SITE;
    await channel.send(message());
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0][0]).toBe(ISSUE_URL);
  });

  it('opens egress:jira-api without opening egress:slack-webhook', async () => {
    setJiraEnv();
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/TEST/HOOK/dummy';
    const policy = fastPolicy();
    const jira = new JiraChannel(policy);
    const slack = new SlackChannel(policy);
    const fetchFn = stubFetch(503);
    await expect(jira.send(message())).rejects.toThrow(/responded 503/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    fetchFn.mockClear();
    await expect(jira.send(message())).rejects.toBeInstanceOf(CircuitOpenError);
    expect(fetchFn).not.toHaveBeenCalled();

    fetchFn.mockResolvedValue(new Response('ok', { status: 200 }));
    await slack.send({
      orgId,
      template: 'policy.violated',
      target: 'slack',
      data: { findingId, policyId, actions: ['notify'] },
    });
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0][0]).toBe('https://hooks.slack.com/services/TEST/HOOK/dummy');
  });
});

import { afterEach, describe, expect, it, vi } from 'vitest';
import { JiraChannel, jiraBasicAuth, jiraIssuePayload } from './jira.channel';
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
});

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
});

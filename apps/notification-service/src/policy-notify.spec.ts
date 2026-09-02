import { afterEach, describe, expect, it, vi } from 'vitest';
import { JiraChannel } from './channels/jira.channel';
import { SlackChannel } from './channels/slack.channel';
import { dispatchPolicyViolated, shouldNotify, shouldTicket } from './policy-notify';

const HOOK = 'https://hooks.slack.com/services/TEST/HOOK/dummy';
const SITE = 'https://acme.atlassian.net';
const TENANT_HOOK = 'https://evil.example/hooks/steal';
const TENANT_JIRA = 'https://evil.example/rest/api/3/issue';
const orgId = '11111111-1111-4111-8111-111111111111';
const findingId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const policyId = '00000000-0000-4000-8000-00000000c7e1';

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
});

describe('shouldNotify / shouldTicket', () => {
  it('is true only when actions include notify', () => {
    expect(shouldNotify(['notify'])).toBe(true);
    expect(shouldNotify(['notify', 'ticket'])).toBe(true);
    expect(shouldNotify(['ticket', 'fail_build'])).toBe(false);
    expect(shouldNotify([])).toBe(false);
  });

  it('is true only when actions include ticket', () => {
    expect(shouldTicket(['ticket'])).toBe(true);
    expect(shouldTicket(['notify', 'ticket'])).toBe(true);
    expect(shouldTicket(['notify', 'fail_build'])).toBe(false);
    expect(shouldTicket([])).toBe(false);
  });
});

describe('dispatchPolicyViolated', () => {
  it('POSTs to the allowlisted Slack hook on policy.violated notify', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const fetchFn = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);

    await dispatchPolicyViolated(
      orgId,
      { findingId, policyId, actions: ['notify'] },
      { slack: new SlackChannel(), jira: new JiraChannel() },
    );

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0][0]).toBe(HOOK);
    const body = JSON.parse(String((fetchFn.mock.calls[0][1] as RequestInit).body));
    expect(body.text).toContain(findingId);
    expect(body.text).toContain(policyId);
  });

  it('POSTs a Jira issue to the allowlisted Atlassian host on ticket', async () => {
    setJiraEnv();
    const fetchFn = vi.fn(async () => new Response(JSON.stringify({ key: 'SEC-1' }), { status: 201 }));
    vi.stubGlobal('fetch', fetchFn);

    await dispatchPolicyViolated(
      orgId,
      { findingId, policyId, actions: ['ticket'] },
      { slack: new SlackChannel(), jira: new JiraChannel() },
    );

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0][0]).toBe(`${SITE}/rest/api/3/issue`);
    expect(new URL(String(fetchFn.mock.calls[0][0])).hostname).toBe('acme.atlassian.net');
  });

  it('does not POST Slack when the matched actions omit notify', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    setJiraEnv();
    const fetchFn = vi.fn(async () => new Response(JSON.stringify({ key: 'SEC-1' }), { status: 201 }));
    vi.stubGlobal('fetch', fetchFn);
    await dispatchPolicyViolated(
      orgId,
      { findingId, policyId, actions: ['ticket'] },
      { slack: new SlackChannel(), jira: new JiraChannel() },
    );
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(String(fetchFn.mock.calls[0][0])).toContain('atlassian.net');
    expect(String(fetchFn.mock.calls[0][0])).not.toContain('hooks.slack.com');
  });

  it('does not POST Jira when the matched actions omit ticket', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    setJiraEnv();
    const fetchFn = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);
    await dispatchPolicyViolated(
      orgId,
      { findingId, policyId, actions: ['notify'] },
      { slack: new SlackChannel(), jira: new JiraChannel() },
    );
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0][0]).toBe(HOOK);
  });

  it('fails closed on missing SLACK_* and never POSTs a tenant webhook', async () => {
    const fetchFn = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);
    const slack = {
      name: 'slack',
      send: (msg: { target: string; data: Record<string, unknown> }) =>
        new SlackChannel().send({
          orgId,
          template: 'policy.violated',
          target: TENANT_HOOK,
          data: { ...msg.data, webhookUrl: TENANT_HOOK },
        }),
    };
    await expect(
      dispatchPolicyViolated(
        orgId,
        { findingId, policyId, actions: ['notify'] },
        { slack, jira: new JiraChannel() },
      ),
    ).rejects.toThrow(/fails closed/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed on missing JIRA_* and never POSTs a tenant Jira URL', async () => {
    const fetchFn = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);
    const jira = {
      name: 'jira',
      send: (msg: { target: string; data: Record<string, unknown> }) =>
        new JiraChannel().send({
          orgId,
          template: 'policy.violated',
          target: TENANT_JIRA,
          data: { ...msg.data, jiraUrl: TENANT_JIRA },
        }),
    };
    await expect(
      dispatchPolicyViolated(
        orgId,
        { findingId, policyId, actions: ['ticket'] },
        { slack: new SlackChannel(), jira },
      ),
    ).rejects.toThrow(/fails closed/);
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

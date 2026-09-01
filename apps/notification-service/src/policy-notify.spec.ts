import { afterEach, describe, expect, it, vi } from 'vitest';
import { SlackChannel } from './channels/slack.channel';
import { notifyPolicyViolated, shouldNotify } from './policy-notify';

const HOOK = 'https://hooks.slack.com/services/TEST/HOOK/dummy';
const TENANT_HOOK = 'https://evil.example/hooks/steal';
const orgId = '11111111-1111-4111-8111-111111111111';
const findingId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const policyId = '00000000-0000-4000-8000-00000000c7e1';

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.SLACK_WEBHOOK_URL;
});

describe('shouldNotify', () => {
  it('is true only when actions include notify', () => {
    expect(shouldNotify(['notify'])).toBe(true);
    expect(shouldNotify(['notify', 'ticket'])).toBe(true);
    expect(shouldNotify(['ticket', 'fail_build'])).toBe(false);
    expect(shouldNotify([])).toBe(false);
  });
});

describe('notifyPolicyViolated', () => {
  it('POSTs to the allowlisted Slack hook on policy.violated notify', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const fetchFn = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);

    await notifyPolicyViolated(
      orgId,
      { findingId, policyId, actions: ['notify'] },
      new SlackChannel(),
    );

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0][0]).toBe(HOOK);
    const body = JSON.parse(String((fetchFn.mock.calls[0][1] as RequestInit).body));
    expect(body.text).toContain(findingId);
    expect(body.text).toContain(policyId);
  });

  it('does not POST when the matched actions omit notify', async () => {
    process.env.SLACK_WEBHOOK_URL = HOOK;
    const fetchFn = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);
    await notifyPolicyViolated(
      orgId,
      { findingId, policyId, actions: ['ticket'] },
      new SlackChannel(),
    );
    expect(fetchFn).not.toHaveBeenCalled();
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
      notifyPolicyViolated(orgId, { findingId, policyId, actions: ['notify'] }, slack),
    ).rejects.toThrow(/fails closed/);
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

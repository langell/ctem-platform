import { describe, expect, it } from 'vitest';
import {
  allowlistedSlackWebhookUrl,
  looksLikeAbsoluteUrl,
  tenantSuppliedWebhookUrls,
} from './slack.egress';

const GOOD = 'https://hooks.slack.com/services/TEST/HOOK/dummy';

describe('allowlistedSlackWebhookUrl', () => {
  it('accepts a canonical incoming-webhook URL', () => {
    expect(allowlistedSlackWebhookUrl(GOOD)).toBe(GOOD);
  });

  it('refuses a non-hooks.slack.com host', () => {
    expect(() => allowlistedSlackWebhookUrl('https://evil.example/hooks/slack')).toThrow(
      /only hooks\.slack\.com/,
    );
  });

  it('refuses a suffix-confusion host', () => {
    expect(() =>
      allowlistedSlackWebhookUrl('https://hooks.slack.com.evil.example/services/TEST/HOOK/dummy'),
    ).toThrow(/only hooks\.slack\.com/);
  });

  it('refuses api.slack.com (not the incoming-webhook host)', () => {
    expect(() => allowlistedSlackWebhookUrl('https://api.slack.com/chat.postMessage')).toThrow(
      /only hooks\.slack\.com/,
    );
  });

  it('refuses http', () => {
    expect(() =>
      allowlistedSlackWebhookUrl('http://hooks.slack.com/services/TEST/HOOK/dummy'),
    ).toThrow(/non-https/);
  });

  it('refuses userinfo and non-default ports', () => {
    expect(() =>
      allowlistedSlackWebhookUrl('https://user:pass@hooks.slack.com/services/TEST/HOOK/dummy'),
    ).toThrow(/userinfo/);
    expect(() =>
      allowlistedSlackWebhookUrl('https://hooks.slack.com:8443/services/TEST/HOOK/dummy'),
    ).toThrow(/port/);
  });

  it('refuses an unexpected path so we do not POST to an arbitrary Slack URL', () => {
    expect(() => allowlistedSlackWebhookUrl('https://hooks.slack.com/')).toThrow(/unexpected path/);
    expect(() => allowlistedSlackWebhookUrl('https://hooks.slack.com/evil')).toThrow(
      /unexpected path/,
    );
  });
});

describe('tenantSuppliedWebhookUrls', () => {
  it('collects absolute URLs from target and data keys and ignores non-URLs', () => {
    expect(
      tenantSuppliedWebhookUrls({
        target: 'https://evil.example/hook',
        data: { webhookUrl: 'https://attacker.test/x', channel: '#sec' },
      }),
    ).toEqual(['https://evil.example/hook', 'https://attacker.test/x']);
  });

  it('does not treat a slack channel name as a URL', () => {
    expect(looksLikeAbsoluteUrl('#security')).toBe(false);
    expect(tenantSuppliedWebhookUrls({ target: 'slack', data: {} })).toEqual([]);
  });
});

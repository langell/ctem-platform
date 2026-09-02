import { describe, expect, it } from 'vitest';
import {
  allowlistedJiraSiteUrl,
  isAtlassianCloudHost,
  jiraCreateIssueUrl,
  looksLikeAbsoluteUrl,
  tenantSuppliedJiraUrls,
} from './jira.egress';

const GOOD = 'https://acme.atlassian.net';

describe('allowlistedJiraSiteUrl', () => {
  it('accepts a canonical Atlassian Cloud site URL', () => {
    expect(allowlistedJiraSiteUrl(GOOD)).toBe(GOOD);
    expect(allowlistedJiraSiteUrl('https://acme.atlassian.net/rest/api/3/issue')).toBe(GOOD);
  });

  it('refuses a non-atlassian.net host', () => {
    expect(() => allowlistedJiraSiteUrl('https://evil.example/jira')).toThrow(/only atlassian\.net/);
  });

  it('refuses a suffix-confusion host', () => {
    expect(() => allowlistedJiraSiteUrl('https://acme.atlassian.net.evil.example/browse/SEC-1')).toThrow(
      /only atlassian\.net/,
    );
    expect(() => allowlistedJiraSiteUrl('https://evilatlassian.net/browse/SEC-1')).toThrow(
      /only atlassian\.net/,
    );
  });

  it('refuses api.atlassian.com and a bare atlassian.net', () => {
    expect(() => allowlistedJiraSiteUrl('https://api.atlassian.com/ex/jira/x')).toThrow(
      /only atlassian\.net/,
    );
    expect(() => allowlistedJiraSiteUrl('https://atlassian.net/')).toThrow(/only atlassian\.net/);
  });

  it('refuses a self-hosted Jira hostname', () => {
    expect(() => allowlistedJiraSiteUrl('https://jira.internal.example/rest/api/3/issue')).toThrow(
      /only atlassian\.net/,
    );
  });

  it('refuses http', () => {
    expect(() => allowlistedJiraSiteUrl('http://acme.atlassian.net')).toThrow(/non-https/);
  });

  it('refuses userinfo and non-default ports', () => {
    expect(() => allowlistedJiraSiteUrl('https://user:pass@acme.atlassian.net')).toThrow(/userinfo/);
    expect(() => allowlistedJiraSiteUrl('https://acme.atlassian.net:8443')).toThrow(/port/);
  });
});

describe('jiraCreateIssueUrl', () => {
  it('builds the Cloud create-issue path on the allowlisted host', () => {
    expect(jiraCreateIssueUrl(GOOD)).toBe('https://acme.atlassian.net/rest/api/3/issue');
  });
});

describe('isAtlassianCloudHost', () => {
  it('accepts {site}.atlassian.net only', () => {
    expect(isAtlassianCloudHost('acme.atlassian.net')).toBe(true);
    expect(isAtlassianCloudHost('ctem-platform.atlassian.net')).toBe(true);
    expect(isAtlassianCloudHost('atlassian.net')).toBe(false);
    expect(isAtlassianCloudHost('api.atlassian.com')).toBe(false);
    expect(isAtlassianCloudHost('acme.atlassian.net.evil.example')).toBe(false);
  });
});

describe('tenantSuppliedJiraUrls', () => {
  it('collects absolute URLs from target and data keys and ignores non-URLs', () => {
    expect(
      tenantSuppliedJiraUrls({
        target: 'https://evil.example/jira',
        data: { jiraUrl: 'https://attacker.test/x', projectKey: 'SEC' },
      }),
    ).toEqual(['https://evil.example/jira', 'https://attacker.test/x']);
  });

  it('does not treat a jira channel name as a URL', () => {
    expect(looksLikeAbsoluteUrl('jira')).toBe(false);
    expect(tenantSuppliedJiraUrls({ target: 'jira', data: {} })).toEqual([]);
  });
});

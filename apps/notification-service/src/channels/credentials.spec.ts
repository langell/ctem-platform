import { afterEach, describe, expect, it } from 'vitest';
import {
  PLATFORM_JIRA_CREDENTIAL_REF,
  PLATFORM_SLACK_CREDENTIAL_REF,
  requireJiraCredentials,
  requireSlackWebhookCredential,
  resolveJiraCredential,
  resolveSlackCredential,
} from './credentials';

afterEach(() => {
  delete process.env.SLACK_WEBHOOK_URL;
  delete process.env.SLACK_NOTIFY_URL;
  delete process.env.JIRA_API_TOKEN;
  delete process.env.JIRA_EMAIL;
  delete process.env.JIRA_BASE_URL;
  delete process.env.JIRA_PROJECT_KEY;
  delete process.env.JIRA_ISSUE_TYPE;
});

describe('resolveSlackCredential', () => {
  it('returns undefined when the ref is null', () => {
    expect(resolveSlackCredential(null)).toBeUndefined();
  });

  it('reads an allowlisted SLACK_* env var', () => {
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/TEST/HOOK/dummy';
    expect(resolveSlackCredential('env:SLACK_WEBHOOK_URL')).toBe(
      'https://hooks.slack.com/services/TEST/HOOK/dummy',
    );
  });

  it('returns undefined when an allowlisted name is unset', () => {
    expect(resolveSlackCredential('env:SLACK_WEBHOOK_URL')).toBeUndefined();
  });

  it('refuses env:DATABASE_URL instead of reading it', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => resolveSlackCredential('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });

  it('refuses env:GITHUB_TOKEN instead of reading it', () => {
    process.env.GITHUB_TOKEN = 'ghp_should_not_leak';
    expect(() => resolveSlackCredential('env:GITHUB_TOKEN')).toThrow(/not allowlisted/);
  });

  it('refuses other replica secrets', () => {
    expect(() => resolveSlackCredential('env:INTERNAL_TOKEN_SECRET')).toThrow(/not allowlisted/);
    expect(() => resolveSlackCredential('env:PATH')).toThrow(/not allowlisted/);
  });

  it('rejects an unsupported scheme', () => {
    expect(() => resolveSlackCredential('vault:slack')).toThrow(/Unsupported credentialRef scheme/);
  });
});

describe('requireSlackWebhookCredential', () => {
  it('fails closed when SLACK_WEBHOOK_URL is missing', () => {
    expect(() => requireSlackWebhookCredential()).toThrow(/fails closed/);
  });

  it('fails closed when SLACK_WEBHOOK_URL is empty', () => {
    process.env.SLACK_WEBHOOK_URL = '';
    expect(() => requireSlackWebhookCredential(PLATFORM_SLACK_CREDENTIAL_REF)).toThrow(
      /fails closed/,
    );
  });

  it('returns the platform secret when set', () => {
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/TEST/HOOK/dummy';
    expect(requireSlackWebhookCredential()).toBe('https://hooks.slack.com/services/TEST/HOOK/dummy');
  });
});

describe('resolveJiraCredential', () => {
  it('returns undefined when the ref is null', () => {
    expect(resolveJiraCredential(null)).toBeUndefined();
  });

  it('reads an allowlisted JIRA_* env var', () => {
    process.env.JIRA_API_TOKEN = 'jira-token';
    expect(resolveJiraCredential('env:JIRA_API_TOKEN')).toBe('jira-token');
  });

  it('returns undefined when an allowlisted name is unset', () => {
    expect(resolveJiraCredential('env:JIRA_API_TOKEN')).toBeUndefined();
  });

  it('refuses env:DATABASE_URL instead of reading it', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => resolveJiraCredential('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });

  it('refuses env:SLACK_WEBHOOK_URL instead of reading it', () => {
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/TEST/HOOK/dummy';
    expect(() => resolveJiraCredential('env:SLACK_WEBHOOK_URL')).toThrow(/not allowlisted/);
  });

  it('refuses other replica secrets', () => {
    expect(() => resolveJiraCredential('env:INTERNAL_TOKEN_SECRET')).toThrow(/not allowlisted/);
    expect(() => resolveJiraCredential('env:PATH')).toThrow(/not allowlisted/);
    expect(() => resolveJiraCredential('env:GITHUB_TOKEN')).toThrow(/not allowlisted/);
  });

  it('rejects an unsupported scheme', () => {
    expect(() => resolveJiraCredential('vault:jira')).toThrow(/Unsupported credentialRef scheme/);
  });
});

describe('requireJiraCredentials', () => {
  it('fails closed when JIRA_API_TOKEN is missing', () => {
    expect(() => requireJiraCredentials()).toThrow(/fails closed/);
  });

  it('fails closed when JIRA_API_TOKEN is empty', () => {
    process.env.JIRA_API_TOKEN = '';
    expect(() => requireJiraCredentials(PLATFORM_JIRA_CREDENTIAL_REF)).toThrow(/fails closed/);
  });

  it('fails closed when a required sibling JIRA_* is missing', () => {
    process.env.JIRA_API_TOKEN = 'jira-token';
    process.env.JIRA_EMAIL = 'sec@example.com';
    expect(() => requireJiraCredentials()).toThrow(/fails closed/);
  });

  it('returns the platform secrets when the JIRA_* set is usable', () => {
    process.env.JIRA_API_TOKEN = 'jira-token';
    process.env.JIRA_EMAIL = 'sec@example.com';
    process.env.JIRA_BASE_URL = 'https://acme.atlassian.net';
    process.env.JIRA_PROJECT_KEY = 'SEC';
    expect(requireJiraCredentials()).toEqual({
      apiToken: 'jira-token',
      email: 'sec@example.com',
      baseUrl: 'https://acme.atlassian.net',
      projectKey: 'SEC',
      issueType: 'Task',
    });
  });
});

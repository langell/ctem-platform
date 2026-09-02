/**
 * Resolves a Slack or Jira credentialRef into a secret. Same platform-operated
 * `env:` pattern as GITHUB_* / GITLAB_* / AWS_*: the ref is a pointer, never
 * the credential itself. Slack reads only `SLACK_*`; Jira reads only `JIRA_*`.
 *
 * A tenant-supplied credentialRef cannot read DATABASE_URL, PATH,
 * INTERNAL_TOKEN_SECRET, GITHUB_TOKEN, or other replica secrets.
 */

/** Platform-controlled Slack names only — not an open read of process.env. */
const SLACK_ENV_ALLOWLIST = /^SLACK_[A-Z0-9_]+$/;

/** Platform-controlled Jira names only — not an open read of process.env. */
const JIRA_ENV_ALLOWLIST = /^JIRA_[A-Z0-9_]+$/;

export const PLATFORM_SLACK_CREDENTIAL_REF = 'env:SLACK_WEBHOOK_URL';
export const PLATFORM_JIRA_CREDENTIAL_REF = 'env:JIRA_API_TOKEN';

function resolveAllowlistedEnv(
  ref: string,
  allowlist: RegExp,
  family: string,
): string | undefined {
  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);

  if (scheme === 'env') {
    if (!key || !allowlist.test(key)) {
      throw new Error(
        `credentialRef 'env:${key || '<empty>'}' is not allowlisted — env: is platform-operated and only ${family} names are permitted`,
      );
    }
    return process.env[key] || undefined;
  }

  throw new Error(
    `Unsupported credentialRef scheme '${scheme}' — only 'env:<VAR>' is implemented`,
  );
}

export function resolveSlackCredential(ref: string | null): string | undefined {
  if (!ref) return undefined;
  return resolveAllowlistedEnv(ref, SLACK_ENV_ALLOWLIST, 'SLACK_*');
}

export function resolveJiraCredential(ref: string | null): string | undefined {
  if (!ref) return undefined;
  return resolveAllowlistedEnv(ref, JIRA_ENV_ALLOWLIST, 'JIRA_*');
}

/**
 * Slack incoming-webhook URL. Fail closed when the platform ref is missing
 * or empty — there is no unauthenticated public path.
 */
export function requireSlackWebhookCredential(
  ref: string = PLATFORM_SLACK_CREDENTIAL_REF,
): string {
  const value = resolveSlackCredential(ref);
  if (!value) {
    throw new Error(
      `credentialRef '${ref}' is set but cannot be used — Slack notify fails closed without a usable SLACK_* secret`,
    );
  }
  return value;
}

export interface JiraCredentials {
  apiToken: string;
  email: string;
  baseUrl: string;
  projectKey: string;
  issueType: string;
}

/**
 * Jira Cloud create-issue credentials. Fail closed when the platform ref or
 * any required sibling JIRA_* is missing or empty — there is no
 * unauthenticated public path, and the site URL is not tenant-writable.
 */
export function requireJiraCredentials(
  ref: string = PLATFORM_JIRA_CREDENTIAL_REF,
): JiraCredentials {
  const apiToken = resolveJiraCredential(ref);
  if (!apiToken) {
    throw new Error(
      `credentialRef '${ref}' is set but cannot be used — Jira ticket fails closed without a usable JIRA_* secret`,
    );
  }

  const email = resolveJiraCredential('env:JIRA_EMAIL');
  const baseUrl = resolveJiraCredential('env:JIRA_BASE_URL');
  const projectKey = resolveJiraCredential('env:JIRA_PROJECT_KEY');
  if (!email || !baseUrl || !projectKey) {
    throw new Error(
      'Jira ticket fails closed without usable JIRA_EMAIL, JIRA_BASE_URL, and JIRA_PROJECT_KEY',
    );
  }

  const issueType = resolveJiraCredential('env:JIRA_ISSUE_TYPE') || 'Task';
  return { apiToken, email, baseUrl, projectKey, issueType };
}

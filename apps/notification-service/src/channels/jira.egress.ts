/**
 * Jira Cloud egress allowlist. Only `https://{site}.atlassian.net` is
 * permitted. A tenant-writable host (or self-hosted Jira) must never become
 * the POST target.
 */

export const ATLASSIAN_CLOUD_SUFFIX = 'atlassian.net';

export class JiraEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JiraEgressError';
  }
}

const SITE_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i;

/** True when a string looks like an absolute URL a tenant might try to inject. */
export function looksLikeAbsoluteUrl(value: string): boolean {
  return /^https?:\/\//i.test(value.trim());
}

/**
 * `{site}.atlassian.net` only — not `atlassian.net`, not `*.atlassian.com`,
 * not a suffix-confused host, not self-hosted Jira.
 */
export function isAtlassianCloudHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (!host.endsWith(`.${ATLASSIAN_CLOUD_SUFFIX}`)) return false;
  const labels = host.split('.');
  return (
    labels.length === 3 &&
    labels[1] === 'atlassian' &&
    labels[2] === 'net' &&
    SITE_LABEL.test(labels[0] ?? '')
  );
}

/**
 * Canonicalize and allowlist a Jira Cloud site URL. Throws rather than
 * returning a host we must not POST to. Path/query are stripped — the
 * create-issue path is platform-owned.
 */
export function allowlistedJiraSiteUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new JiraEgressError('Refusing unparseable Jira URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new JiraEgressError(
      `Refusing non-https Jira URL — only https://*.${ATLASSIAN_CLOUD_SUFFIX} is permitted`,
    );
  }
  if (!isAtlassianCloudHost(parsed.hostname)) {
    throw new JiraEgressError(
      `Refusing Jira host '${parsed.hostname}' — only ${ATLASSIAN_CLOUD_SUFFIX} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new JiraEgressError('Refusing Jira URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new JiraEgressError('Refusing Jira URL that embeds userinfo');
  }
  return `https://${parsed.hostname.toLowerCase()}`;
}

/** Platform create-issue URL on the allowlisted Cloud site. */
export function jiraCreateIssueUrl(rawSite: string): string {
  return `${allowlistedJiraSiteUrl(rawSite)}/rest/api/3/issue`;
}

/**
 * Tenant-writable fields on the notification message (target, data.jiraUrl,
 * body/query-shaped keys) must never choose the egress host.
 */
export function tenantSuppliedJiraUrls(input: {
  target?: string;
  data?: Record<string, unknown>;
}): string[] {
  const found: string[] = [];
  const consider = (value: unknown) => {
    if (typeof value === 'string' && looksLikeAbsoluteUrl(value)) found.push(value);
  };
  consider(input.target);
  const data = input.data ?? {};
  for (const key of [
    'webhookUrl',
    'webhook',
    'url',
    'target',
    'hookUrl',
    'jiraUrl',
    'jiraBaseUrl',
    'jiraHost',
    'atlassianUrl',
    'issueUrl',
    'baseUrl',
  ]) {
    consider(data[key]);
  }
  return found;
}

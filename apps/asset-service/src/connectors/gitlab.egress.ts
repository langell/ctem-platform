/**
 * GitLab discovery egress. gitlab.com is the default origin. A self-hosted
 * host is only the explicit connector `baseUrl` — https, no userinfo, no git@.
 * Tenant-writable extra host fields must never become the API or clone target.
 */

export const GITLAB_COM_HOST = 'gitlab.com';
export const GITLAB_COM_ORIGIN = 'https://gitlab.com';
export const GITLAB_COM_API_URL = 'https://gitlab.com/api/v4';

export class GitLabEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GitLabEgressError';
  }
}

export interface GitLabOrigin {
  host: string;
  origin: string;
  apiUrl: string;
}

export const GITLAB_COM: GitLabOrigin = {
  host: GITLAB_COM_HOST,
  origin: GITLAB_COM_ORIGIN,
  apiUrl: GITLAB_COM_API_URL,
};

/**
 * Keys a tenant might use to point listing/clone at a host other than
 * `baseUrl`. `baseUrl` itself is the one allowed host field.
 */
export const EXTRA_GITLAB_HOST_KEYS = [
  'host',
  'apiUrl',
  'apiEndpoint',
  'url',
  'endpoint',
  'cloneHost',
  'cloneUrl',
  'hosts',
  'gitHost',
  'gitlabHost',
  'hostname',
  'customEndpoint',
  'gitUrl',
  'sshUrl',
  'httpUrl',
] as const;

export function refuseExtraGitLabHosts(config: Record<string, unknown>): void {
  for (const key of EXTRA_GITLAB_HOST_KEYS) {
    const value = config[key];
    if (value != null && value !== '') {
      throw new GitLabEgressError(
        `Refusing tenant-writable GitLab host (${key}) — only connector baseUrl may set the host`,
      );
    }
  }
}

export function canonicalGitLabHostname(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === 'www.gitlab.com') return GITLAB_COM_HOST;
  return host;
}

/**
 * Canonicalize connector `baseUrl` (or default gitlab.com). Throws rather
 * than returning a host we must not list or clone.
 */
export function parseGitLabBaseUrl(raw: string | undefined | null): GitLabOrigin {
  if (raw == null || String(raw).trim() === '') return GITLAB_COM;

  const trimmed = String(raw).trim();
  if (trimmed.startsWith('git@') || trimmed.startsWith('ssh:') || trimmed.startsWith('ssh@')) {
    throw new GitLabEgressError(`Refusing git@ / ssh GitLab baseUrl: ${trimmed}`);
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new GitLabEgressError('Refusing unparseable GitLab baseUrl');
  }
  if (parsed.protocol !== 'https:') {
    throw new GitLabEgressError('Refusing non-https GitLab baseUrl — only https is permitted');
  }
  if (parsed.username || parsed.password) {
    throw new GitLabEgressError('Refusing GitLab baseUrl that embeds userinfo');
  }
  if (parsed.port && parsed.port !== '443') {
    throw new GitLabEgressError('Refusing GitLab baseUrl with a non-default port');
  }
  const host = canonicalGitLabHostname(parsed.hostname);
  if (!host) {
    throw new GitLabEgressError('Refusing GitLab baseUrl with an empty host');
  }
  if (host === GITLAB_COM_HOST) return GITLAB_COM;
  return {
    host,
    origin: `https://${host}`,
    apiUrl: `https://${host}/api/v4`,
  };
}

/**
 * Re-run the host allowlist on an API URL we are about to fetch. A caller
 * cannot bypass egress by handing a foreign URL here.
 */
export function allowlistedGitLabApiUrl(raw: string, origin: GitLabOrigin): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new GitLabEgressError('Refusing unparseable GitLab API URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new GitLabEgressError(
      `Refusing non-https GitLab API URL — only https://${origin.host} is permitted`,
    );
  }
  const host = canonicalGitLabHostname(parsed.hostname);
  if (host !== origin.host) {
    throw new GitLabEgressError(
      `Refusing GitLab API host '${parsed.hostname}' — only ${origin.host} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new GitLabEgressError('Refusing GitLab API URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new GitLabEgressError('Refusing GitLab API URL that embeds userinfo');
  }
  if (!parsed.pathname.startsWith('/api/v4')) {
    throw new GitLabEgressError(`Refusing GitLab API URL with an unexpected path: ${raw}`);
  }
  return parsed.href;
}

/**
 * GitLab Commit Status egress. Twin of asset-service `gitlab.egress.ts`:
 * gitlab.com is the default origin. A self-hosted host is only the org GitLab
 * AssetConnector `baseUrl` already used for that asset/integration — https,
 * no userinfo, no git@. Tenant scan options cannot choose the API host
 * (`EXTRA_GITLAB_HOST_KEYS` on the scan are ignored and never become origin).
 */

export const GITLAB_COM_HOST = 'gitlab.com';
export const GITLAB_COM_ORIGIN = 'https://gitlab.com';
export const GITLAB_COM_API_URL = 'https://gitlab.com/api/v4';

export class GitLabStatusesEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GitLabStatusesEgressError';
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
 * Keys a tenant might use to point statuses at a host other than the
 * connector `baseUrl`. Ignored on scan options; never the API origin.
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
      throw new GitLabStatusesEgressError(
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
 * than returning a host we must not POST a GITLAB_* token to.
 */
export function parseGitLabBaseUrl(raw: string | undefined | null): GitLabOrigin {
  if (raw == null || String(raw).trim() === '') return GITLAB_COM;

  const trimmed = String(raw).trim();
  if (trimmed.startsWith('git@') || trimmed.startsWith('ssh:') || trimmed.startsWith('ssh@')) {
    throw new GitLabStatusesEgressError(`Refusing git@ / ssh GitLab baseUrl: ${trimmed}`);
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new GitLabStatusesEgressError('Refusing unparseable GitLab baseUrl');
  }
  if (parsed.protocol !== 'https:') {
    throw new GitLabStatusesEgressError('Refusing non-https GitLab baseUrl — only https is permitted');
  }
  if (parsed.username || parsed.password) {
    throw new GitLabStatusesEgressError('Refusing GitLab baseUrl that embeds userinfo');
  }
  if (parsed.port && parsed.port !== '443') {
    throw new GitLabStatusesEgressError('Refusing GitLab baseUrl with a non-default port');
  }
  const host = canonicalGitLabHostname(parsed.hostname);
  if (!host) {
    throw new GitLabStatusesEgressError('Refusing GitLab baseUrl with an empty host');
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
    throw new GitLabStatusesEgressError('Refusing unparseable GitLab API URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new GitLabStatusesEgressError(
      `Refusing non-https GitLab API URL — only https://${origin.host} is permitted`,
    );
  }
  const host = canonicalGitLabHostname(parsed.hostname);
  if (host !== origin.host) {
    throw new GitLabStatusesEgressError(
      `Refusing GitLab API host '${parsed.hostname}' — only ${origin.host} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new GitLabStatusesEgressError('Refusing GitLab API URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new GitLabStatusesEgressError('Refusing GitLab API URL that embeds userinfo');
  }
  if (!parsed.pathname.startsWith('/api/v4')) {
    throw new GitLabStatusesEgressError(`Refusing GitLab API URL with an unexpected path: ${raw}`);
  }
  return parsed.href;
}

/** Relative `/api/v4/...` path on the allowlisted origin. */
export function gitlabStatusesApiUrl(origin: GitLabOrigin, pathAndQuery: string): string {
  if (!pathAndQuery.startsWith('/')) {
    throw new GitLabStatusesEgressError('Refusing GitLab Commit Status path that is not relative');
  }
  return allowlistedGitLabApiUrl(`${origin.apiUrl}${pathAndQuery}`, origin);
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

/**
 * Origin for statuses: first GitLab AssetConnector on the scan's jobs
 * (its `config.baseUrl`, same parse as discovery), else gitlab.com.
 * Scan-option host keys are not read here.
 */
export function gitLabOriginFromScanJobs(
  jobs: Array<{
    asset?: { integration?: { provider?: string | null; config?: unknown } | null } | null;
  }>,
): GitLabOrigin {
  for (const job of jobs) {
    const integ = job.asset?.integration;
    if (!integ || integ.provider !== 'gitlab') continue;
    const config = asRecord(integ.config);
    const baseUrl = typeof config.baseUrl === 'string' ? config.baseUrl : undefined;
    return parseGitLabBaseUrl(baseUrl);
  }
  return GITLAB_COM;
}

/** GET existing commit statuses (filter by name; `all=true` so a prior POST is visible). */
export function listCommitStatusesUrl(
  origin: GitLabOrigin,
  projectId: string,
  sha: string,
  name: string,
): string {
  const params = new URLSearchParams({ name, all: 'true' });
  return gitlabStatusesApiUrl(
    origin,
    `/projects/${encodeURIComponent(projectId)}/repository/commits/${encodeURIComponent(sha)}/statuses?${params}`,
  );
}

/** POST one Commit Status. GitLab has no PATCH for statuses. */
export function createCommitStatusUrl(origin: GitLabOrigin, projectId: string, sha: string): string {
  return gitlabStatusesApiUrl(
    origin,
    `/projects/${encodeURIComponent(projectId)}/statuses/${encodeURIComponent(sha)}`,
  );
}

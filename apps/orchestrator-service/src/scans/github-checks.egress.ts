/**
 * GitHub Checks egress allowlist. The publisher talks to `api.github.com` only
 * (HTTPS/443). No GitHub Enterprise host, no tenant `baseUrl`, and no follow of
 * platform `GITHUB_API_URL` off api.github.com (that env is for discovery stubs).
 *
 * Tenant scan options cannot choose the API host. `repository` / `owner` /
 * `repo` are identifiers in the path, not endpoints.
 */

export const GITHUB_API_HOST = 'api.github.com';
export const GITHUB_API_ORIGIN = 'https://api.github.com';

export class GithubChecksEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GithubChecksEgressError';
  }
}

/** Keys a tenant might use to point Checks at a non-GitHub.com API host. Ignored. */
export const TENANT_CHECKS_ENDPOINT_KEYS = [
  'endpoint',
  'apiUrl',
  'apiEndpoint',
  'host',
  'baseUrl',
  'url',
  'endpointUrl',
  'customEndpoint',
  'apiHost',
  'githubUrl',
  'githubHost',
  'githubApiUrl',
  'gheHost',
  'enterpriseUrl',
] as const;

export function isGithubApiHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === GITHUB_API_HOST;
}

/**
 * Canonicalize and allowlist a GitHub API URL. Throws rather than returning a
 * host we must not send a GITHUB_* token to (including github.com and GHE).
 */
export function allowlistedGithubApiUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new GithubChecksEgressError('Refusing unparseable GitHub API URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new GithubChecksEgressError(
      `Refusing non-https GitHub API URL — only https://${GITHUB_API_HOST} is permitted`,
    );
  }
  if (!isGithubApiHost(parsed.hostname)) {
    throw new GithubChecksEgressError(
      `Refusing GitHub API host '${parsed.hostname}' — only ${GITHUB_API_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new GithubChecksEgressError('Refusing GitHub API URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new GithubChecksEgressError('Refusing GitHub API URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  return `https://${GITHUB_API_HOST}${path}${parsed.search}`;
}

/** Build a Checks REST URL on api.github.com. Path must be relative (`/repos/...`). */
export function githubChecksApiUrl(pathAndQuery: string): string {
  if (!pathAndQuery.startsWith('/')) {
    throw new GithubChecksEgressError('Refusing GitHub Checks path that is not relative');
  }
  return allowlistedGithubApiUrl(`${GITHUB_API_ORIGIN}${pathAndQuery}`);
}

export function checkRunsUrl(owner: string, repo: string): string {
  return githubChecksApiUrl(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/check-runs`,
  );
}

export function checkRunUrl(owner: string, repo: string, checkRunId: number): string {
  return githubChecksApiUrl(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/check-runs/${checkRunId}`,
  );
}

export function listCheckRunsUrl(owner: string, repo: string, sha: string, checkName: string): string {
  const params = new URLSearchParams({
    check_name: checkName,
    filter: 'latest',
    per_page: '100',
  });
  return githubChecksApiUrl(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits/${encodeURIComponent(sha)}/check-runs?${params}`,
  );
}

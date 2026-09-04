/**
 * GHCR inventory egress allowlist. Listing talks to GitHub's Packages REST
 * on `api.github.com` only (HTTPS/443). Never `ghcr.io` — that host is for
 * layer/blob pull, which this slice does not do. Tenant config/body/query
 * cannot set a registry or API host.
 *
 * Platform `GITHUB_API_URL` already defaults to `https://api.github.com`.
 * This module canonicalizes that same host; it does not accept a tenant
 * override and does not follow `GITHUB_API_URL` off api.github.com.
 */

export const GITHUB_API_HOST = 'api.github.com';
export const GITHUB_API_ORIGIN = 'https://api.github.com';

export class GhcrEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GhcrEgressError';
  }
}

/** Keys a tenant might use to point discovery at a non-GitHub host. */
export const TENANT_ENDPOINT_KEYS = [
  'endpoint',
  'apiUrl',
  'apiEndpoint',
  'host',
  'baseUrl',
  'url',
  'endpointUrl',
  'customEndpoint',
  'apiHost',
  'registryUrl',
  'registryHost',
  'ghcrUrl',
  'ghcrHost',
  'githubUrl',
  'githubHost',
] as const;

export function isGithubApiHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === GITHUB_API_HOST;
}

/**
 * Canonicalize and allowlist a GitHub API URL. Throws rather than returning
 * a host we must not send a GITHUB_* token to (including ghcr.io).
 */
export function allowlistedGithubApiUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new GhcrEgressError('Refusing unparseable GitHub API URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new GhcrEgressError(
      `Refusing non-https GitHub API URL — only https://${GITHUB_API_HOST} is permitted`,
    );
  }
  if (!isGithubApiHost(parsed.hostname)) {
    throw new GhcrEgressError(
      `Refusing GitHub API host '${parsed.hostname}' — only ${GITHUB_API_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new GhcrEgressError('Refusing GitHub API URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new GhcrEgressError('Refusing GitHub API URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  return `https://${GITHUB_API_HOST}${path}${parsed.search}`;
}

/** Complete-signal is Link rel=next, not page length. */
export function nextRelFromLinkHeader(link: string | null | undefined): string | undefined {
  if (!link || typeof link !== 'string') return undefined;
  for (const part of link.split(',')) {
    const match = part.match(/<([^>]+)>\s*;\s*rel\s*=\s*"?next"?/i);
    const href = match?.[1]?.trim();
    if (href) return href;
  }
  return undefined;
}

export function ghcrPackagesUrl(owner: string, ownerType: 'user' | 'org'): string {
  const encoded = encodeURIComponent(owner);
  const path = ownerType === 'org' ? `/orgs/${encoded}/packages` : `/users/${encoded}/packages`;
  return allowlistedGithubApiUrl(
    `${GITHUB_API_ORIGIN}${path}?package_type=container&per_page=100`,
  );
}

export function ghcrPackageVersionsUrl(
  owner: string,
  ownerType: 'user' | 'org',
  packageName: string,
): string {
  const encodedOwner = encodeURIComponent(owner);
  // GitHub: a `/` in the package name must be `%2F` — encodeURIComponent does that.
  const encodedPkg = encodeURIComponent(packageName);
  const path =
    ownerType === 'org'
      ? `/orgs/${encodedOwner}/packages/container/${encodedPkg}/versions`
      : `/users/${encodedOwner}/packages/container/${encodedPkg}/versions`;
  return allowlistedGithubApiUrl(`${GITHUB_API_ORIGIN}${path}?per_page=100&state=active`);
}

/**
 * Tenant-writable integration config (and body/query-shaped keys) must never
 * choose the GitHub API or GHCR registry host. `owner` is an identifier;
 * it is not an endpoint.
 */
export function refuseTenantWritableEndpoint(config: Record<string, unknown>): void {
  for (const key of TENANT_ENDPOINT_KEYS) {
    const value = config[key];
    if (value != null && value !== '') {
      throw new GhcrEgressError(
        `Refusing tenant-writable GHCR endpoint (${key}) — API hosts are GitHub's, not tenant-configurable`,
      );
    }
  }
  const owner = config.owner;
  if (typeof owner === 'string' && /^https?:\/\//i.test(owner.trim())) {
    throw new GhcrEgressError(
      "Refusing tenant-writable GHCR endpoint (owner) — API hosts are GitHub's, not tenant-configurable",
    );
  }
}

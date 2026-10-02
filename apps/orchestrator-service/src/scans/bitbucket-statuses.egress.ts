/**
 * Bitbucket Cloud build-status egress. Twin of asset-service
 * `bitbucket.egress.ts` host pin, narrowed to the build-status path:
 * `https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/commit/{commit}/statuses/build`
 * (HTTPS/443 only). No Bitbucket Server / Data Center, no tenant `baseUrl` /
 * `apiUrl` / `bitbucketHost`. Workspace and repo slug are identifiers, not hosts.
 */

export const BITBUCKET_API_HOST = 'api.bitbucket.org';
export const BITBUCKET_API_ORIGIN = 'https://api.bitbucket.org';

/**
 * Workspace ids and repo slugs. Path identifiers — never a URL or host.
 * Letters, digits, underscore, hyphen, and period; no `..`, no leading or
 * trailing dot (those normalize into a different path).
 */
export const BITBUCKET_ID_RE = /^(?!.*\.\.)(?!\.)(?!.*\.$)[\w.-]+$/;

const BITBUCKET_HOST_IDS = new Set(['bitbucket.org', 'api.bitbucket.org', 'www.bitbucket.org']);

export class BitbucketStatusesEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BitbucketStatusesEgressError';
  }
}

/**
 * Keys a tenant might use to point a build status at a host other than
 * pinned `api.bitbucket.org`. Ignored on scan options; never the API origin.
 */
export const TENANT_BITBUCKET_HOST_KEYS = [
  'endpoint',
  'apiUrl',
  'apiEndpoint',
  'host',
  'baseUrl',
  'endpointUrl',
  'customEndpoint',
  'apiHost',
  'hostname',
  'authority',
  'bitbucketUrl',
  'bitbucketHost',
  'bitbucketApiUrl',
  'bitbucketEndpoint',
  'bitbucketServer',
  'bitbucketServerUrl',
  'server',
  'serverUrl',
  'dataCenter',
  'dataCenterUrl',
  'dataCenterHost',
  'cloneHost',
  'cloneUrl',
  'htmlUrl',
  'gitHost',
  'gitUrl',
  'sshUrl',
  'httpUrl',
  'scmUrl',
  'origin',
] as const;

const EXTRA_HOST_KEY_RE = /^EXTRA_.+_HOST(_KEYS)?$/i;

export function isBitbucketApiHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === BITBUCKET_API_HOST;
}

export function assertBitbucketWorkspace(workspace: string): string {
  return assertBitbucketId(workspace, 'workspace');
}

export function assertBitbucketRepoSlug(slug: string): string {
  return assertBitbucketId(slug, 'repo slug');
}

function assertBitbucketId(value: string, label: 'workspace' | 'repo slug'): string {
  if (!BITBUCKET_ID_RE.test(value) || /^https?:\/\//i.test(value)) {
    throw new BitbucketStatusesEgressError(
      `Refusing Bitbucket ${label} '${value}' — not a valid Bitbucket identifier`,
    );
  }
  const lower = value.toLowerCase();
  if (BITBUCKET_HOST_IDS.has(lower) || lower.endsWith('.bitbucket.org')) {
    throw new BitbucketStatusesEgressError(
      `Refusing Bitbucket ${label} '${value}' — identifiers are not hosts`,
    );
  }
  return value;
}

function valueIsSet(value: unknown): boolean {
  return value != null && value !== '';
}

/**
 * Tenant-writable scan or connector fields must never choose the Bitbucket
 * API host. No Server / Data Center `baseUrl` in this slice.
 */
export function refuseTenantBitbucketHost(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (EXTRA_HOST_KEY_RE.test(key) && valueIsSet(config[key])) {
      throw new BitbucketStatusesEgressError(
        `Refusing tenant-writable Bitbucket host (${key}) — EXTRA_*_HOST_KEYS is not permitted`,
      );
    }
  }
  for (const key of TENANT_BITBUCKET_HOST_KEYS) {
    if (valueIsSet(config[key])) {
      throw new BitbucketStatusesEgressError(
        `Refusing tenant-writable Bitbucket host (${key}) — API host is api.bitbucket.org, not tenant-configurable`,
      );
    }
  }
}

/**
 * Re-run the host allowlist on a build-status URL we are about to fetch.
 * A caller cannot bypass egress by handing a Server, lookalike, or tenant URL.
 */
export function allowlistedBitbucketBuildStatusUrl(
  raw: string,
  workspace: string,
  repoSlug: string,
  sha: string,
): string {
  const ws = assertBitbucketWorkspace(workspace);
  const repo = assertBitbucketRepoSlug(repoSlug);
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new BitbucketStatusesEgressError('Refusing unparseable Bitbucket API URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new BitbucketStatusesEgressError(
      `Refusing non-https Bitbucket API URL — only https://${BITBUCKET_API_HOST} is permitted`,
    );
  }
  if (!isBitbucketApiHost(parsed.hostname)) {
    throw new BitbucketStatusesEgressError(
      `Refusing Bitbucket API host '${parsed.hostname}' — only ${BITBUCKET_API_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new BitbucketStatusesEgressError('Refusing Bitbucket API URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new BitbucketStatusesEgressError('Refusing Bitbucket API URL that embeds userinfo');
  }
  if (parsed.search || parsed.hash) {
    throw new BitbucketStatusesEgressError(
      'Refusing Bitbucket build-status URL with a query or fragment',
    );
  }
  assertBuildStatusPath(parsed.pathname || '/', ws, repo, sha);
  return `https://${BITBUCKET_API_HOST}${parsed.pathname}`;
}

function decodeSegment(segment: string, label: string): string {
  if (/%2f/i.test(segment) || /%5c/i.test(segment)) {
    throw new BitbucketStatusesEgressError(
      `Refusing Bitbucket API path segment — ${label} is a single path segment`,
    );
  }
  try {
    return decodeURIComponent(segment);
  } catch {
    throw new BitbucketStatusesEgressError(
      `Refusing Bitbucket API URL with an undecodable ${label}`,
    );
  }
}

function assertBuildStatusPath(
  pathname: string,
  workspace: string,
  repoSlug: string,
  sha: string,
): void {
  const parts = pathname.split('/').filter(Boolean);
  if (
    parts.length !== 8 ||
    parts[0] !== '2.0' ||
    parts[1] !== 'repositories' ||
    parts[4] !== 'commit' ||
    parts[6] !== 'statuses' ||
    parts[7] !== 'build'
  ) {
    throw new BitbucketStatusesEgressError(
      `Refusing Bitbucket API path '${pathname}' — only /2.0/repositories/{workspace}/{repo_slug}/commit/{commit}/statuses/build is permitted`,
    );
  }
  const ws = decodeSegment(parts[2] ?? '', 'workspace');
  const repo = decodeSegment(parts[3] ?? '', 'repo slug');
  const commit = decodeSegment(parts[5] ?? '', 'commit');
  if (ws !== workspace || repo !== repoSlug || commit.toLowerCase() !== sha.toLowerCase()) {
    throw new BitbucketStatusesEgressError(
      `Refusing Bitbucket API path '${pathname}' — workspace, repo slug, and commit must match the scan context`,
    );
  }
}

/** POST/upsert one build status. Bitbucket replaces an existing status with the same `key`. */
export function bitbucketBuildStatusUrl(workspace: string, repoSlug: string, sha: string): string {
  const ws = assertBitbucketWorkspace(workspace);
  const repo = assertBitbucketRepoSlug(repoSlug);
  if (!/^[0-9a-f]{40}$/i.test(sha)) {
    throw new BitbucketStatusesEgressError(
      'Refusing Bitbucket build status without a full 40-char commit SHA',
    );
  }
  const commit = sha.toLowerCase();
  const url = `${BITBUCKET_API_ORIGIN}/2.0/repositories/${encodeURIComponent(ws)}/${encodeURIComponent(repo)}/commit/${encodeURIComponent(commit)}/statuses/build`;
  return allowlistedBitbucketBuildStatusUrl(url, ws, repo, commit);
}

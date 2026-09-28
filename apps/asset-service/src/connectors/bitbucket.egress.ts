/**
 * Bitbucket Cloud inventory egress. Listing talks only to
 * `https://api.bitbucket.org/2.0/repositories/{workspace}` (HTTPS/443).
 * Clone and html URLs are synthesized on `bitbucket.org`. Never follow API
 * `links.html` / clone hrefs, and never accept a Bitbucket Server / Data
 * Center host or a tenant `baseUrl`.
 *
 * `workspace` and `repo_slug` are identifiers, not hosts.
 */

export const BITBUCKET_API_HOST = 'api.bitbucket.org';
export const BITBUCKET_API_ORIGIN = 'https://api.bitbucket.org';
export const BITBUCKET_WEB_HOST = 'bitbucket.org';
export const BITBUCKET_WEB_ORIGIN = 'https://bitbucket.org';

/**
 * Workspace ids and repo slugs. Path identifiers — never a URL or host.
 * Letters, digits, underscore, hyphen, and period; no `..`, no leading or
 * trailing dot (those normalize into a different path).
 */
export const BITBUCKET_ID_RE = /^(?!.*\.\.)(?!\.)(?!.*\.$)[\w.-]+$/;

const BITBUCKET_HOST_IDS = new Set(['bitbucket.org', 'api.bitbucket.org', 'www.bitbucket.org']);

export class BitbucketEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BitbucketEgressError';
  }
}

/**
 * Keys a tenant might use to point listing or clone at a host other than
 * pinned Bitbucket Cloud. `workspace` is an identifier; it is not an endpoint.
 */
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

/** GitLab-style extra-host allowlist. Bitbucket Cloud refuses this pattern entirely. */
export const EXTRA_HOST_KEY_RE = /^EXTRA_.+_HOST(_KEYS)?$/i;

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
    throw new BitbucketEgressError(
      `Refusing Bitbucket ${label} '${value}' — not a valid Bitbucket identifier`,
    );
  }
  const lower = value.toLowerCase();
  if (BITBUCKET_HOST_IDS.has(lower) || lower.endsWith('.bitbucket.org')) {
    throw new BitbucketEgressError(
      `Refusing Bitbucket ${label} '${value}' — identifiers are not hosts`,
    );
  }
  return value;
}

/**
 * Canonicalize and allowlist a Bitbucket Cloud API URL for one workspace.
 * Throws rather than returning a host we must not send a BITBUCKET_* token
 * to (suffix confusion, lookalikes, bitbucket.org HTML, Server/DC paths).
 */
export function allowlistedBitbucketApiUrl(raw: string, workspace: string): string {
  const id = assertBitbucketWorkspace(workspace);
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new BitbucketEgressError('Refusing unparseable Bitbucket API URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new BitbucketEgressError(
      `Refusing non-https Bitbucket API URL — only https://${BITBUCKET_API_HOST} is permitted`,
    );
  }
  if (!isBitbucketApiHost(parsed.hostname)) {
    throw new BitbucketEgressError(
      `Refusing Bitbucket API host '${parsed.hostname}' — only ${BITBUCKET_API_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new BitbucketEgressError('Refusing Bitbucket API URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new BitbucketEgressError('Refusing Bitbucket API URL that embeds userinfo');
  }
  assertRepositoryListPath(parsed.pathname || '/', id);
  return `https://${BITBUCKET_API_HOST}${parsed.pathname}${parsed.search}`;
}

function assertRepositoryListPath(pathname: string, workspace: string): void {
  const parts = pathname.split('/').filter(Boolean);
  if (parts.length !== 3 || parts[0] !== '2.0' || parts[1] !== 'repositories') {
    throw new BitbucketEgressError(
      `Refusing Bitbucket API path '${pathname}' — only /2.0/repositories/${workspace} is permitted`,
    );
  }
  const segment = parts[2] ?? '';
  if (segment.includes('%2f') || segment.includes('%2F') || segment.includes('%5c') || segment.includes('%5C')) {
    throw new BitbucketEgressError(
      `Refusing Bitbucket API path '${pathname}' — workspace is a single path segment`,
    );
  }
  let decoded: string;
  try {
    decoded = decodeURIComponent(segment);
  } catch {
    throw new BitbucketEgressError('Refusing Bitbucket API URL with an undecodable workspace');
  }
  if (decoded.toLowerCase() !== workspace.toLowerCase() || decoded.includes('/') || decoded.includes('\\')) {
    throw new BitbucketEgressError(
      `Refusing Bitbucket API path '${pathname}' — only /2.0/repositories/${workspace} is permitted`,
    );
  }
}

/** First-page listing. Later pages must still pass {@link allowlistedBitbucketApiUrl}. */
export function bitbucketRepositoriesUrl(workspace: string, page: number, pagelen: number): string {
  const id = assertBitbucketWorkspace(workspace);
  if (!Number.isInteger(page) || page < 1) {
    throw new BitbucketEgressError('Refusing Bitbucket repository listing with a non-positive page');
  }
  if (!Number.isInteger(pagelen) || pagelen < 1 || pagelen > 100) {
    throw new BitbucketEgressError('Refusing Bitbucket repository listing with pagelen outside 1..100');
  }
  const url = new URL(`${BITBUCKET_API_ORIGIN}/2.0/repositories/${encodeURIComponent(id)}`);
  url.searchParams.set('pagelen', String(pagelen));
  url.searchParams.set('page', String(page));
  return allowlistedBitbucketApiUrl(url.href, id);
}

/** Display URL. Always `bitbucket.org`, never an API `links.html.href`. */
export function bitbucketHtmlUrl(workspace: string, slug: string): string {
  const ws = assertBitbucketWorkspace(workspace);
  const repo = assertBitbucketRepoSlug(slug);
  return `${BITBUCKET_WEB_ORIGIN}/${ws}/${repo}`;
}

/** Clone URL. Always `bitbucket.org`, never an API clone href. */
export function bitbucketCloneUrl(workspace: string, slug: string): string {
  return `${bitbucketHtmlUrl(workspace, slug)}.git`;
}

function valueIsSet(value: unknown): boolean {
  return value != null && value !== '';
}

function refuseIfUrl(value: unknown, field: string): void {
  if (typeof value === 'string' && /^https?:\/\//i.test(value.trim())) {
    throw new BitbucketEgressError(
      `Refusing tenant-writable Bitbucket endpoint (${field}) — API host is api.bitbucket.org, not tenant-configurable`,
    );
  }
}

/**
 * Tenant-writable integration config must never choose the Bitbucket API or
 * clone host. No Server / Data Center `baseUrl` in this slice.
 */
export function refuseTenantWritableEndpoint(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (EXTRA_HOST_KEY_RE.test(key) && valueIsSet(config[key])) {
      throw new BitbucketEgressError(
        `Refusing tenant-writable Bitbucket endpoint (${key}) — EXTRA_*_HOST_KEYS is not permitted`,
      );
    }
  }
  for (const key of TENANT_ENDPOINT_KEYS) {
    if (valueIsSet(config[key])) {
      throw new BitbucketEgressError(
        `Refusing tenant-writable Bitbucket endpoint (${key}) — API host is api.bitbucket.org, not tenant-configurable`,
      );
    }
  }
  refuseIfUrl(config.workspace, 'workspace');
  const repos = config.repos;
  if (Array.isArray(repos)) {
    for (const item of repos) refuseIfUrl(item, 'repos');
  }
}

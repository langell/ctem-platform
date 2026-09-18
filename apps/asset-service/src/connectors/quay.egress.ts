/**
 * Quay.io inventory egress allowlist. Listing talks to Quay's REST API on
 * `quay.io` only (HTTPS/443), under `/api/v1/...`. Never `/v2/` (OCI pull),
 * never CDN/registry blob hosts, never a self-hosted Quay / Quay Enterprise
 * host. Tenant config/body/query cannot set a registry or API host.
 *
 * `namespace` and `repository` are identifiers, not hosts.
 */

export const QUAY_API_HOST = 'quay.io';
export const QUAY_API_ORIGIN = 'https://quay.io';

/**
 * Quay org / user ids. Path identifiers — never a registry URL or host.
 * Quay allows letters, digits, underscore, hyphen, and period.
 */
export const QUAY_NAMESPACE_RE = /^[a-z0-9][a-z0-9._-]{0,253}$/i;

/**
 * Repository names are path ids (`team/api`), never registry URLs.
 */
export const QUAY_REPOSITORY_RE =
  /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/i;

export class QuayEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'QuayEgressError';
  }
}

/** Keys a tenant might use to point discovery at a non-quay.io host. */
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
  'registryUrl',
  'registryHost',
  'registryEndpoint',
  'quayUrl',
  'quayHost',
  'quayIo',
  'quayEndpoint',
  'enterpriseUrl',
  'enterpriseHost',
  'selfHosted',
  'selfHostedUrl',
  'dockerHost',
  'dockerUrl',
  'containerRegistryUrl',
  'containerRegistryHost',
  'loginServer',
  'tokenUrl',
  'tokenUri',
  'token_uri',
] as const;

/** GitLab-style extra-host allowlist. Quay refuses this pattern entirely. */
export const EXTRA_HOST_KEY_RE = /^EXTRA_.+_HOST(_KEYS)?$/i;

export function isQuayApiHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === QUAY_API_HOST;
}

function assertQuayApiPath(path: string): void {
  if (path !== '/api/v1' && !path.startsWith('/api/v1/')) {
    throw new QuayEgressError(
      `Refusing Quay API path '${path}' — only https://${QUAY_API_HOST}/api/v1/ is permitted`,
    );
  }
}

/**
 * Canonicalize and allowlist a Quay API URL. Throws rather than returning
 * a host we must not send a QUAY_* token to (including suffix-confusion,
 * lookalikes, self-hosted Quay, and OCI `/v2/` pull paths on quay.io).
 */
export function allowlistedQuayApiUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new QuayEgressError('Refusing unparseable Quay API URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new QuayEgressError(
      `Refusing non-https Quay API URL — only https://${QUAY_API_HOST} is permitted`,
    );
  }
  if (!isQuayApiHost(parsed.hostname)) {
    throw new QuayEgressError(
      `Refusing Quay API host '${parsed.hostname}' — only ${QUAY_API_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new QuayEgressError('Refusing Quay API URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new QuayEgressError('Refusing Quay API URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  assertQuayApiPath(path);
  return `https://${QUAY_API_HOST}${path}${parsed.search}`;
}

export function assertQuayNamespace(namespace: string): string {
  if (!QUAY_NAMESPACE_RE.test(namespace) || /^https?:\/\//i.test(namespace)) {
    throw new QuayEgressError(
      `Refusing Quay namespace '${namespace}' — not a valid Quay organization or user identifier`,
    );
  }
  return namespace;
}

export function assertQuayRepository(repository: string): string {
  if (!QUAY_REPOSITORY_RE.test(repository) || /^https?:\/\//i.test(repository)) {
    throw new QuayEgressError(
      `Refusing Quay repository '${repository}' — not a valid repository identifier`,
    );
  }
  return repository;
}

/** `/api/v1/repository/{namespace}/{repository}` — ids, never hosts. */
export function quayRepositoryApiPath(namespace: string, repository: string): string {
  assertQuayNamespace(namespace);
  assertQuayRepository(repository);
  const ns = encodeURIComponent(namespace);
  const repo = repository
    .split('/')
    .map((seg) => encodeURIComponent(seg))
    .join('/');
  return `/api/v1/repository/${ns}/${repo}`;
}

/**
 * List repositories in a namespace. `nextPage` is an opaque token, or a
 * leftover full URL that must still pin to quay.io /api/v1.
 */
export function quayRepositoriesUrl(namespace: string, nextPage?: string): string {
  assertQuayNamespace(namespace);
  if (nextPage && /^https?:\/\//i.test(nextPage)) {
    return allowlistedQuayApiUrl(nextPage);
  }
  const url = new URL(`${QUAY_API_ORIGIN}/api/v1/repository`);
  url.searchParams.set('namespace', namespace);
  url.searchParams.set('repo_kind', 'image');
  if (nextPage) url.searchParams.set('next_page', nextPage);
  return allowlistedQuayApiUrl(url.href);
}

/** List tags for one repository. `page` is a 1-based integer, not a host. */
export function quayTagsUrl(namespace: string, repository: string, page: number): string {
  if (!Number.isInteger(page) || page < 1) {
    throw new QuayEgressError('Refusing Quay tag listing with a non-positive page');
  }
  const path = quayRepositoryApiPath(namespace, repository);
  return allowlistedQuayApiUrl(
    `${QUAY_API_ORIGIN}${path}/tag?limit=100&page=${page}&onlyActiveTags=true`,
  );
}

function valueIsSet(value: unknown): boolean {
  return value != null && value !== '';
}

function refuseIfUrl(value: unknown, field: string): void {
  if (typeof value === 'string' && /^https?:\/\//i.test(value.trim())) {
    throw new QuayEgressError(
      `Refusing tenant-writable Quay endpoint (${field}) — API hosts are quay.io, not tenant-configurable`,
    );
  }
}

/**
 * Tenant-writable integration config (and body/query-shaped keys) must never
 * choose the Quay API or pull host — including self-hosted Quay. `namespace`
 * is an identifier; it is not an endpoint.
 */
export function refuseTenantWritableEndpoint(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (EXTRA_HOST_KEY_RE.test(key) && valueIsSet(config[key])) {
      throw new QuayEgressError(
        `Refusing tenant-writable Quay endpoint (${key}) — EXTRA_*_HOST_KEYS is not permitted`,
      );
    }
  }
  for (const key of TENANT_ENDPOINT_KEYS) {
    if (valueIsSet(config[key])) {
      throw new QuayEgressError(
        `Refusing tenant-writable Quay endpoint (${key}) — API hosts are quay.io, not tenant-configurable`,
      );
    }
  }
  refuseIfUrl(config.namespace, 'namespace');
  const repositories = config.repositories;
  if (Array.isArray(repositories)) {
    for (const item of repositories) refuseIfUrl(item, 'repositories');
  }
}

/**
 * Docker Hub inventory egress allowlist. Listing talks to Docker Hub's Hub
 * API on `hub.docker.com` only (HTTPS/443), including the login/token POST
 * used for private namespaces. Never the pull-plane hosts — those are for
 * layer/blob pull, which this slice does not do. Tenant config/body/query
 * cannot set a registry, index, or Hub host.
 *
 * Namespace and repository are identifiers, not hosts.
 */

export const DOCKERHUB_HUB_HOST = 'hub.docker.com';
export const DOCKERHUB_HUB_ORIGIN = 'https://hub.docker.com';

/** Docker Hub org/user and repository ids (`[\w.-]+` style). Never hosts. */
export const DOCKERHUB_NAMESPACE_RE = /^[\w.-]+$/;
export const DOCKERHUB_REPOSITORY_RE = /^[\w.-]+$/;

export class DockerhubEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DockerhubEgressError';
  }
}

/**
 * Keys a tenant might use to point discovery at a non-Hub host, including
 * pull-plane index/registry URLs.
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
  'authority',
  'loginUrl',
  'tokenUrl',
  'tokenUri',
  'token_uri',
  'authUrl',
  'authHost',
  'registryUrl',
  'registryHost',
  'registry',
  'registryEndpoint',
  'hubUrl',
  'hubHost',
  'hubEndpoint',
  'dockerhubUrl',
  'dockerHubUrl',
  'dockerhubHost',
  'dockerHubHost',
  'index',
  'indexUrl',
  'indexHost',
  'indexDockerIo',
  'dockerIo',
  'dockerIoUrl',
  'dockerIoHost',
  'dockerHost',
  'dockerUrl',
  'containerRegistryUrl',
  'containerRegistryHost',
] as const;

/** GitLab-style extra-host allowlist. Docker Hub refuses this pattern entirely. */
export const EXTRA_HOST_KEY_RE = /^EXTRA_.+_HOST(_KEYS)?$/i;

export function isDockerhubHubHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === DOCKERHUB_HUB_HOST;
}

function isForbiddenDockerHostId(value: string): boolean {
  const id = value.toLowerCase().replace(/\.$/, '');
  return (
    id === DOCKERHUB_HUB_HOST ||
    /docker\.(io|com)$/i.test(id)
  );
}

function isDockerhubListingPath(pathname: string): boolean {
  const path = pathname.replace(/\/+$/, '') || '/';
  if (path.includes('/blobs') || path.includes('/manifests')) return false;
  if (path === '/v2/users/login') return true;
  if (path === '/v2/auth/token') return true;
  if (/^\/v2\/repositories\/[^/]+$/.test(path)) return true;
  if (/^\/v2\/repositories\/[^/]+\/[^/]+\/tags$/.test(path)) return true;
  return false;
}

/**
 * Canonicalize and allowlist a Docker Hub Hub API URL. Throws rather than
 * returning a host we must not send DOCKERHUB_* credentials to.
 */
export function allowlistedDockerhubUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new DockerhubEgressError('Refusing unparseable Docker Hub API URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new DockerhubEgressError(
      `Refusing non-https Docker Hub API URL — only https://${DOCKERHUB_HUB_HOST} is permitted`,
    );
  }
  if (!isDockerhubHubHost(parsed.hostname)) {
    throw new DockerhubEgressError(
      `Refusing Docker Hub API host '${parsed.hostname}' — only ${DOCKERHUB_HUB_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new DockerhubEgressError('Refusing Docker Hub API URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new DockerhubEgressError('Refusing Docker Hub API URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  if (!isDockerhubListingPath(path)) {
    throw new DockerhubEgressError(
      `Refusing Docker Hub API path '${path}' — only Hub listing and login on ${DOCKERHUB_HUB_HOST} are permitted`,
    );
  }
  return `https://${DOCKERHUB_HUB_HOST}${path}${parsed.search}`;
}

export function assertDockerhubNamespace(namespace: string): string {
  const trimmed = namespace.trim();
  if (
    /^https?:\/\//i.test(trimmed) ||
    !DOCKERHUB_NAMESPACE_RE.test(trimmed) ||
    isForbiddenDockerHostId(trimmed)
  ) {
    throw new DockerhubEgressError(
      `Refusing Docker Hub namespace '${namespace}' — not a valid namespace identifier`,
    );
  }
  return trimmed;
}

export function assertDockerhubRepository(repository: string): string {
  const trimmed = repository.trim();
  if (
    /^https?:\/\//i.test(trimmed) ||
    !DOCKERHUB_REPOSITORY_RE.test(trimmed) ||
    isForbiddenDockerHostId(trimmed)
  ) {
    throw new DockerhubEgressError(
      `Refusing Docker Hub repository '${repository}' — not a valid repository identifier`,
    );
  }
  return trimmed;
}

/** Hub login (JWT) on the same allowlisted host — never a tenant URL. */
export function dockerhubLoginUrl(): string {
  return allowlistedDockerhubUrl(`${DOCKERHUB_HUB_ORIGIN}/v2/users/login/`);
}

/** Optional Hub token endpoint; still `hub.docker.com`, never a tenant URL. */
export function dockerhubTokenUrl(): string {
  return allowlistedDockerhubUrl(`${DOCKERHUB_HUB_ORIGIN}/v2/auth/token/`);
}

export function dockerhubRepositoriesUrl(namespace: string): string {
  const ns = assertDockerhubNamespace(namespace);
  return allowlistedDockerhubUrl(
    `${DOCKERHUB_HUB_ORIGIN}/v2/repositories/${encodeURIComponent(ns)}/?page_size=100`,
  );
}

export function dockerhubTagsUrl(namespace: string, repository: string): string {
  const ns = assertDockerhubNamespace(namespace);
  const repo = assertDockerhubRepository(repository);
  return allowlistedDockerhubUrl(
    `${DOCKERHUB_HUB_ORIGIN}/v2/repositories/${encodeURIComponent(ns)}/${encodeURIComponent(repo)}/tags/?page_size=100`,
  );
}

function valueIsSet(value: unknown): boolean {
  return value != null && value !== '';
}

function refuseIfUrl(value: unknown, field: string): void {
  if (typeof value === 'string' && /^https?:\/\//i.test(value.trim())) {
    throw new DockerhubEgressError(
      `Refusing tenant-writable Docker Hub endpoint (${field}) — API hosts are Docker Hub's, not tenant-configurable`,
    );
  }
}

function refuseIfHostShaped(value: unknown, field: string): void {
  refuseIfUrl(value, field);
  if (typeof value === 'string' && isForbiddenDockerHostId(value.trim())) {
    throw new DockerhubEgressError(
      `Refusing tenant-writable Docker Hub endpoint (${field}) — API hosts are Docker Hub's, not tenant-configurable`,
    );
  }
}

/**
 * Tenant-writable integration config (and body/query-shaped keys) must never
 * choose the Hub API, index, or registry host. `namespace` is an identifier;
 * it is not an endpoint.
 */
export function refuseTenantWritableEndpoint(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (EXTRA_HOST_KEY_RE.test(key) && valueIsSet(config[key])) {
      throw new DockerhubEgressError(
        `Refusing tenant-writable Docker Hub endpoint (${key}) — EXTRA_*_HOST_KEYS is not permitted`,
      );
    }
  }
  for (const key of TENANT_ENDPOINT_KEYS) {
    if (valueIsSet(config[key])) {
      throw new DockerhubEgressError(
        `Refusing tenant-writable Docker Hub endpoint (${key}) — API hosts are Docker Hub's, not tenant-configurable`,
      );
    }
  }
  refuseIfHostShaped(config.namespace, 'namespace');
  const repositories = config.repositories;
  if (Array.isArray(repositories)) {
    for (const item of repositories) refuseIfHostShaped(item, 'repositories');
  }
}

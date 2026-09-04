/**
 * Container-scan egress allowlist. Layer pull talks to `ghcr.io` only
 * (HTTPS/443). Tenant config/body/query/options cannot set a registry host.
 * Identity is `ghcr:owner/name@sha256:<digest>` from GHCR discovery — never a
 * tag, never ECR/GCR/ACR/Docker Hub.
 */

export const GHCR_REGISTRY_HOST = 'ghcr.io';
export const GHCR_REGISTRY_ORIGIN = 'https://ghcr.io';

/** GHCR serves blob bodies via this GitHub CDN after a 302 from ghcr.io. */
export const GHCR_BLOB_CDN_HOST = 'pkg-containers.githubusercontent.com';

export class ContainerEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContainerEgressError';
  }
}

/** Keys a tenant might use to point the pull at a non-GHCR registry. */
export const TENANT_REGISTRY_KEYS = [
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
  'registry',
  'imageRegistry',
  'ghcrUrl',
  'ghcrHost',
  'githubUrl',
  'githubHost',
  'dockerHost',
  'ecrUrl',
  'gcrUrl',
  'acrUrl',
] as const;

export function isGhcrRegistryHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === GHCR_REGISTRY_HOST;
}

export function isGhcrBlobCdnHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === GHCR_BLOB_CDN_HOST;
}

function canonicalizeHttpsHost(
  raw: string,
  allowed: (hostname: string) => boolean,
  label: string,
): URL {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ContainerEgressError(`Refusing unparseable ${label} URL`);
  }
  if (parsed.protocol !== 'https:') {
    throw new ContainerEgressError(`Refusing non-https ${label} URL — only https is permitted`);
  }
  if (!allowed(parsed.hostname)) {
    throw new ContainerEgressError(
      `Refusing ${label} host '${parsed.hostname}' — only ${GHCR_REGISTRY_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new ContainerEgressError(`Refusing ${label} URL with a non-default port`);
  }
  if (parsed.username || parsed.password) {
    throw new ContainerEgressError(`Refusing ${label} URL that embeds userinfo`);
  }
  return parsed;
}

/**
 * Canonicalize a URL we will GET on ghcr.io (manifest, blob, token). Throws
 * rather than returning a host we must not send a GITHUB_* token to.
 */
export function allowlistedGhcrUrl(raw: string): string {
  const parsed = canonicalizeHttpsHost(raw, isGhcrRegistryHost, 'GHCR registry');
  const path = parsed.pathname || '/';
  if (!path.startsWith('/v2/') && path !== '/token' && !path.startsWith('/token')) {
    throw new ContainerEgressError(
      `Refusing GHCR path '${path}' — only /v2/ and /token on ${GHCR_REGISTRY_HOST} are permitted`,
    );
  }
  return `https://${GHCR_REGISTRY_HOST}${path}${parsed.search}`;
}

/**
 * Blob GET on ghcr.io may 302 to GitHub's package CDN. Follow only that host
 * (HTTPS/443, no userinfo) and never attach the GITHUB_* bearer to it.
 */
export function allowlistedGhcrBlobRedirect(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ContainerEgressError('Refusing unparseable GHCR blob redirect');
  }
  if (parsed.protocol !== 'https:') {
    throw new ContainerEgressError('Refusing non-https GHCR blob redirect');
  }
  if (parsed.port && parsed.port !== '443') {
    throw new ContainerEgressError('Refusing GHCR blob redirect with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new ContainerEgressError('Refusing GHCR blob redirect that embeds userinfo');
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (host === GHCR_REGISTRY_HOST) {
    return allowlistedGhcrUrl(raw);
  }
  if (host === GHCR_BLOB_CDN_HOST) {
    return `https://${GHCR_BLOB_CDN_HOST}${parsed.pathname}${parsed.search}`;
  }
  throw new ContainerEgressError(
    `Refusing GHCR blob redirect host '${parsed.hostname}' — only ${GHCR_REGISTRY_HOST} and ${GHCR_BLOB_CDN_HOST} are allowlisted`,
  );
}

export function ghcrTokenUrl(owner: string, name: string): string {
  const repo = `${owner}/${name}`;
  return allowlistedGhcrUrl(
    `${GHCR_REGISTRY_ORIGIN}/token?service=ghcr.io&scope=${encodeURIComponent(`repository:${repo}:pull`)}`,
  );
}

export function ghcrManifestUrl(owner: string, name: string, digest: string): string {
  return allowlistedGhcrUrl(`${GHCR_REGISTRY_ORIGIN}/v2/${encodeRepoPath(owner, name)}/manifests/${digest}`);
}

export function ghcrBlobUrl(owner: string, name: string, digest: string): string {
  return allowlistedGhcrUrl(`${GHCR_REGISTRY_ORIGIN}/v2/${encodeRepoPath(owner, name)}/blobs/${digest}`);
}

/** OCI name is owner/package; encode each segment, keep slashes. */
function encodeRepoPath(owner: string, name: string): string {
  return [owner, ...name.split('/')].map(encodeURIComponent).join('/');
}

/**
 * Tenant-writable scan options / target attributes must never choose the
 * registry host. `owner` is an identifier; it is not an endpoint.
 */
export function refuseTenantWritableRegistry(config: Record<string, unknown>): void {
  for (const key of TENANT_REGISTRY_KEYS) {
    const value = config[key];
    if (value != null && value !== '') {
      throw new ContainerEgressError(
        `Refusing tenant-writable container registry endpoint (${key}) — pulls are ghcr.io only, not tenant-configurable`,
      );
    }
  }
  const owner = config.owner;
  if (typeof owner === 'string' && /^https?:\/\//i.test(owner.trim())) {
    throw new ContainerEgressError(
      "Refusing tenant-writable container registry endpoint (owner) — pulls are ghcr.io only, not tenant-configurable",
    );
  }
}

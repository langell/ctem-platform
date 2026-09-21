/**
 * Quay.io pull-plane egress. Manifest + blob + token GET talk only to
 * exact host `quay.io` (HTTPS/443). Token path is `/v2/auth`. Never
 * `/api/v1/` (inventory listing), never a CDN host, never a self-hosted
 * Quay / Quay Enterprise host. Namespace / repository are ids, not hosts.
 * Tenant config cannot set a registry / auth / quayUrl host.
 */

export const QUAY_REGISTRY_HOST = 'quay.io';

/**
 * Token `service=` value for Quay's registry. This is a well-known
 * service name sent as a query parameter — never a connect host.
 */
export const QUAY_REGISTRY_SERVICE = 'quay.io';

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

export function isQuayRegistryHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === QUAY_REGISTRY_HOST;
}

/** Alias: token and registry share exact host `quay.io`. */
export function isQuayAuthHost(hostname: string): boolean {
  return isQuayRegistryHost(hostname);
}

export function isForbiddenQuayHostId(value: string): boolean {
  const id = value.toLowerCase().replace(/\.$/, '');
  return id === QUAY_REGISTRY_HOST || id.endsWith('.quay.io') || /quay\.io/i.test(id);
}

export function assertQuayNamespace(namespace: string): string {
  const trimmed = namespace.trim();
  if (
    /^https?:\/\//i.test(trimmed) ||
    !QUAY_NAMESPACE_RE.test(trimmed) ||
    isForbiddenQuayHostId(trimmed)
  ) {
    throw new QuayEgressError(
      `Refusing Quay namespace '${namespace}' — not a valid Quay organization or user identifier`,
    );
  }
  return trimmed;
}

export function assertQuayRepository(repository: string): string {
  const trimmed = repository.trim();
  if (
    /^https?:\/\//i.test(trimmed) ||
    !QUAY_REPOSITORY_RE.test(trimmed) ||
    isForbiddenQuayHostId(trimmed)
  ) {
    throw new QuayEgressError(
      `Refusing Quay repository '${repository}' — not a valid repository identifier`,
    );
  }
  return trimmed;
}

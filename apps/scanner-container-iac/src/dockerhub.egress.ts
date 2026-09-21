/**
 * Docker Hub pull-plane egress. Manifest + blob GET talks only to
 * `registry-1.docker.io`. Token GET talks only to `auth.docker.io`.
 * HTTPS/443. Never `hub.docker.com` (inventory listing), never
 * `index.docker.io`, never a CDN host. Namespace / repository are ids,
 * not hosts. Tenant config cannot set a registry / index / auth host.
 */

export const DOCKERHUB_REGISTRY_HOST = 'registry-1.docker.io';
export const DOCKERHUB_AUTH_HOST = 'auth.docker.io';

/**
 * Token `service=` value for Docker Hub's registry. This is a well-known
 * service name sent as a query parameter — never a connect host.
 */
export const DOCKERHUB_REGISTRY_SERVICE = 'registry.docker.io';

/** Docker Hub org/user and repository ids (`[\w.-]+` style). Never hosts. */
export const DOCKERHUB_NAMESPACE_RE = /^[\w.-]+$/;
export const DOCKERHUB_REPOSITORY_RE = /^[\w.-]+$/;

export class DockerhubEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DockerhubEgressError';
  }
}

export function isDockerhubRegistryHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === DOCKERHUB_REGISTRY_HOST;
}

export function isDockerhubAuthHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === DOCKERHUB_AUTH_HOST;
}

export function isForbiddenDockerHostId(value: string): boolean {
  const id = value.toLowerCase().replace(/\.$/, '');
  return (
    id === 'hub.docker.com' ||
    id === DOCKERHUB_REGISTRY_HOST ||
    id === DOCKERHUB_AUTH_HOST ||
    id === 'index.docker.io' ||
    id === 'docker.io' ||
    /docker\.(io|com)$/i.test(id)
  );
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

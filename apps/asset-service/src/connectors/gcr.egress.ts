/**
 * GCR / Artifact Registry inventory egress allowlist. Listing talks to
 * Google's Artifact Registry API on `artifactregistry.googleapis.com`
 * (HTTPS/443) plus the existing GCP token exchange on
 * `oauth2.googleapis.com`. Never `gcr.io`, `*.pkg.dev`, or OCI `/v2/`
 * pull hosts — those are for layer/blob pull, which this slice does not
 * do. Tenant config/body/query cannot set a registry or API host.
 *
 * Location and projectId are identifiers, not hosts.
 */

import {
  GCP_API_SUFFIX,
  GCP_PROJECT_ID_RE,
  allowlistedGcpUrl,
  assertGcpProjectId,
} from './gcp.egress';

export const AR_API_HOST = 'artifactregistry.googleapis.com';

/** Inventory-only Artifact Registry scope. Not cloud-platform, not write. */
export const GCR_OAUTH_SCOPE = 'https://www.googleapis.com/auth/artifactregistry.readonly';

/**
 * Artifact Registry location ids (`us`, `us-central1`, `europe-west1`).
 * Multi-region and region ids only — never `*.pkg.dev` / `gcr.io` hosts.
 */
export const GCP_LOCATION_ID_RE = /^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Artifact Registry repository ids. Periods are allowed (`gcr.io` is a
 * valid migrated-GCR repository id) — they are path segments, never hosts.
 */
export const GCR_REPOSITORY_ID_RE = /^[a-z][a-z0-9._-]{0,61}[a-z0-9]$/;

/** Google's list-all-locations parent. Internal only — not a tenant location. */
export const GCR_ALL_LOCATIONS = '-';

export class GcrEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GcrEgressError';
  }
}

/** Keys a tenant might use to point discovery at a non-AR API host. */
export const TENANT_ENDPOINT_KEYS = [
  'endpoint',
  'apiUrl',
  'apiEndpoint',
  'host',
  'baseUrl',
  'url',
  'endpointUrl',
  'gcpEndpoint',
  'customEndpoint',
  'tokenUri',
  'tokenUrl',
  'token_uri',
  'universeDomain',
  'universe_domain',
  'apiHost',
  'registryUrl',
  'registryHost',
  'registry',
  'gcrUrl',
  'gcrHost',
  'gcrEndpoint',
  'gcrIo',
  'artifactRegistryUrl',
  'artifactRegistryHost',
  'arUrl',
  'arHost',
  'dockerHost',
  'dockerUrl',
  'pkgDevHost',
  'pkgDevUrl',
] as const;

/** GitLab-style extra-host allowlist. GCR refuses this pattern entirely. */
export const EXTRA_HOST_KEY_RE = /^EXTRA_.+_HOST(_KEYS)?$/i;

export function isArtifactRegistryApiHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === AR_API_HOST;
}

/**
 * Canonicalize and allowlist an Artifact Registry API URL. Throws rather
 * than returning a host we must not send GCP_* keys to (including gcr.io
 * and *.pkg.dev).
 */
export function allowlistedGcrApiUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new GcrEgressError('Refusing unparseable Artifact Registry API URL');
  }
  const canonical = allowlistedGcpUrl(raw);
  if (!isArtifactRegistryApiHost(parsed.hostname)) {
    throw new GcrEgressError(
      `Refusing Artifact Registry API host '${parsed.hostname}' — only ${AR_API_HOST} is allowlisted`,
    );
  }
  return canonical;
}

export function assertGcpLocationId(location: string): string {
  if (!GCP_LOCATION_ID_RE.test(location)) {
    throw new GcrEgressError(
      `Refusing GCP location '${location}' — not a valid Artifact Registry location identifier`,
    );
  }
  return location;
}

/** List parent: a location id, or `-` for every location. */
export function assertGcrListLocation(location: string): string {
  if (location === GCR_ALL_LOCATIONS) return location;
  return assertGcpLocationId(location);
}

export function assertGcrRepositoryId(repository: string): string {
  if (!GCR_REPOSITORY_ID_RE.test(repository)) {
    throw new GcrEgressError(
      `Refusing Artifact Registry repository '${repository}' — not a valid repository identifier`,
    );
  }
  return repository;
}

/** Platform host for ListRepositories. location is an id (`-` = all). */
export function gcrRepositoriesUrl(projectId: string, location: string): string {
  assertGcpProjectId(projectId);
  assertGcrListLocation(location);
  return allowlistedGcrApiUrl(
    `https://${AR_API_HOST}/v1/projects/${encodeURIComponent(projectId)}/locations/${encodeURIComponent(location)}/repositories`,
  );
}

/** Platform host for ListDockerImages. location must be a concrete id. */
export function gcrDockerImagesUrl(
  projectId: string,
  location: string,
  repository: string,
): string {
  assertGcpProjectId(projectId);
  assertGcpLocationId(location);
  assertGcrRepositoryId(repository);
  return allowlistedGcrApiUrl(
    `https://${AR_API_HOST}/v1/projects/${encodeURIComponent(projectId)}/locations/${encodeURIComponent(location)}/repositories/${encodeURIComponent(repository)}/dockerImages`,
  );
}

function valueIsSet(value: unknown): boolean {
  return value != null && value !== '';
}

function refuseIfUrl(value: unknown, field: string): void {
  if (typeof value === 'string' && /^https?:\/\//i.test(value.trim())) {
    throw new GcrEgressError(
      `Refusing tenant-writable GCR endpoint (${field}) — API hosts are Google's, not tenant-configurable`,
    );
  }
}

/**
 * Tenant-writable integration config (and body/query-shaped keys) must never
 * choose the Artifact Registry / GCR API or pull host. projectId / location
 * are identifiers; they are not endpoints.
 */
export function refuseTenantWritableEndpoint(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (EXTRA_HOST_KEY_RE.test(key) && valueIsSet(config[key])) {
      throw new GcrEgressError(
        `Refusing tenant-writable GCR endpoint (${key}) — EXTRA_*_HOST_KEYS is not permitted`,
      );
    }
  }
  for (const key of TENANT_ENDPOINT_KEYS) {
    if (valueIsSet(config[key])) {
      throw new GcrEgressError(
        `Refusing tenant-writable GCR endpoint (${key}) — API hosts are Google's, not tenant-configurable`,
      );
    }
  }
  refuseIfUrl(config.projectId, 'projectId');
  refuseIfUrl(config.project, 'project');
  refuseIfUrl(config.location, 'location');
  const locations = config.locations;
  if (Array.isArray(locations)) {
    for (const item of locations) refuseIfUrl(item, 'locations');
  }
  const repositories = config.repositories;
  if (Array.isArray(repositories)) {
    for (const item of repositories) refuseIfUrl(item, 'repositories');
  }
}

export { GCP_API_SUFFIX, GCP_PROJECT_ID_RE };

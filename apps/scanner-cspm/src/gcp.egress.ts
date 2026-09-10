/**
 * GCP API egress allowlist. Hosts are Google's (`*.googleapis.com`), never
 * tenant-writable. Same hosts as GCP discovery — a config/body/query
 * endpoint must not become the destination for `GCP_*` signing keys.
 */

export const GCP_API_SUFFIX = 'googleapis.com';
export const GCP_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const GCP_COMPUTE_HOST = 'compute.googleapis.com';
export const GCP_STORAGE_HOST = 'storage.googleapis.com';
export const GCP_OAUTH_HOST = 'oauth2.googleapis.com';

/**
 * GCP project ids: 6–30 chars, start with a letter, lowercase letters /
 * digits / hyphens, not ending in a hyphen. This is an identifier, not a host.
 */
export const GCP_PROJECT_ID_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;

export class GcpEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GcpEgressError';
  }
}

/** Keys a tenant might use to point discovery at a non-Google host. */
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
] as const;

export function isGcpApiHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === GCP_API_SUFFIX) return true;
  if (!host.endsWith(`.${GCP_API_SUFFIX}`)) return false;
  const labels = host.split('.');
  return labels.at(-2) === 'googleapis' && labels.at(-1) === 'com';
}

/**
 * Canonicalize and allowlist a GCP API URL. Throws rather than returning a
 * host we must not send keys to.
 */
export function allowlistedGcpUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new GcpEgressError('Refusing unparseable GCP API URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new GcpEgressError(
      `Refusing non-https GCP API URL — only https://*.${GCP_API_SUFFIX} is permitted`,
    );
  }
  if (!isGcpApiHost(parsed.hostname)) {
    throw new GcpEgressError(
      `Refusing GCP API host '${parsed.hostname}' — only ${GCP_API_SUFFIX} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new GcpEgressError('Refusing GCP API URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new GcpEgressError('Refusing GCP API URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  return `https://${parsed.hostname.toLowerCase()}${path}${parsed.search}`;
}

export function assertGcpProjectId(projectId: string): string {
  if (!GCP_PROJECT_ID_RE.test(projectId)) {
    throw new GcpEgressError(
      `Refusing GCP projectId '${projectId}' — not a valid GCP project identifier`,
    );
  }
  return projectId;
}

/** Build the platform Compute Engine URL. projectId is an id, never a host. */
export function gcpComputeUrl(projectId: string, resourcePath: string): string {
  assertGcpProjectId(projectId);
  if (!resourcePath.startsWith('/')) {
    throw new GcpEgressError('Refusing GCP compute path that is not rooted');
  }
  return allowlistedGcpUrl(
    `https://${GCP_COMPUTE_HOST}/compute/v1/projects/${encodeURIComponent(projectId)}${resourcePath}`,
  );
}

/** Cloud Storage JSON API list-buckets. Never a tenant-derived bucket host. */
export function gcpStorageBucketsUrl(projectId: string): string {
  assertGcpProjectId(projectId);
  return allowlistedGcpUrl(
    `https://${GCP_STORAGE_HOST}/storage/v1/b?project=${encodeURIComponent(projectId)}`,
  );
}

/**
 * GCS bucket names are identifiers in a path on storage.googleapis.com —
 * never a `{bucket}.storage.googleapis.com` host.
 */
export const GCS_BUCKET_RE = /^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$/;
export const GCP_RESOURCE_NAME_RE = /^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;

export function assertGcsBucketName(bucket: string): string {
  if (/^https?:\/\//i.test(bucket) || bucket.includes('/') || !GCS_BUCKET_RE.test(bucket)) {
    throw new GcpEgressError(
      `Refusing GCS bucket '${bucket}' — not a valid Cloud Storage bucket identifier`,
    );
  }
  return bucket;
}

export function assertGcpResourceName(name: string, field: string): string {
  if (/^https?:\/\//i.test(name) || name.includes('/') || !GCP_RESOURCE_NAME_RE.test(name)) {
    throw new GcpEgressError(`Refusing GCP ${field} '${name}' — not a valid GCP resource identifier`);
  }
  return name;
}

/** JSON API get-bucket. Path-style on storage.googleapis.com only. */
export function gcpStorageBucketUrl(bucket: string, query: Record<string, string> = {}): string {
  assertGcsBucketName(bucket);
  const params = new URLSearchParams(query);
  const search = params.toString() ? `?${params.toString()}` : '';
  return allowlistedGcpUrl(
    `https://${GCP_STORAGE_HOST}/storage/v1/b/${encodeURIComponent(bucket)}${search}`,
  );
}

/** JSON API getIamPolicy. Bindings stay on storage.googleapis.com. */
export function gcpStorageBucketIamUrl(bucket: string, pageToken?: string): string {
  const query: Record<string, string> = {};
  if (pageToken) query.pageToken = pageToken;
  const params = new URLSearchParams(query);
  const search = params.toString() ? `?${params.toString()}` : '';
  assertGcsBucketName(bucket);
  return allowlistedGcpUrl(
    `https://${GCP_STORAGE_HOST}/storage/v1/b/${encodeURIComponent(bucket)}/iam${search}`,
  );
}

export function gcpFirewallUrl(projectId: string, name: string): string {
  return gcpComputeUrl(projectId, `/global/firewalls/${encodeURIComponent(assertGcpResourceName(name, 'firewall'))}`);
}

/**
 * Tenant-writable integration config (and body/query-shaped keys) must never
 * choose the GCP API host. projectId is allowed; it is not an endpoint.
 */
export function refuseTenantWritableEndpoint(config: Record<string, unknown>): void {
  for (const key of TENANT_ENDPOINT_KEYS) {
    const value = config[key];
    if (value != null && value !== '') {
      throw new GcpEgressError(
        `Refusing tenant-writable GCP endpoint (${key}) — API hosts are Google's, not tenant-configurable`,
      );
    }
  }
  const projectId = config.projectId;
  if (typeof projectId === 'string' && /^https?:\/\//i.test(projectId.trim())) {
    throw new GcpEgressError(
      "Refusing tenant-writable GCP endpoint (projectId) — API hosts are Google's, not tenant-configurable",
    );
  }
}

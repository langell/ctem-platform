/**
 * GCP token-exchange egress for GCR / Artifact Registry digest pull.
 * The service-account JWT is posted only to `oauth2.googleapis.com`
 * (HTTPS/443) — the same token host GCR inventory / GCP connectors use.
 * Docker layer pull uses `{location}-docker.pkg.dev` (see container.egress).
 * Tenant config cannot set token_uri / universeDomain.
 */

export const GCP_API_SUFFIX = 'googleapis.com';
export const GCP_OAUTH_HOST = 'oauth2.googleapis.com';
export const GCP_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const GCP_STORAGE_HOST = 'storage.googleapis.com';

/**
 * GCP project ids: 6–30 chars, start with a letter, lowercase letters /
 * digits / hyphens, not ending in a hyphen. This is an identifier, not a host.
 */
export const GCP_PROJECT_ID_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;

/**
 * Artifact Registry location ids (`us`, `us-central1`, `europe-west1`).
 * Same regex as GCR inventory. Never `*.pkg.dev` / `gcr.io` hosts.
 */
export const GCP_LOCATION_ID_RE = /^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Artifact Registry repository ids. Periods are allowed (`gcr.io` is a
 * valid migrated-GCR repository id) — they are path segments, never hosts.
 */
export const GCR_REPOSITORY_ID_RE = /^[a-z][a-z0-9._-]{0,61}[a-z0-9]$/;

export class GcpEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GcpEgressError';
  }
}

export function isGcpOauthHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === GCP_OAUTH_HOST;
}

/**
 * Canonicalize the Google OAuth token URL. Throws rather than returning a
 * host we must not send the service-account JWT to.
 */
export function allowlistedGcpTokenUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new GcpEgressError('Refusing unparseable GCP token URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new GcpEgressError('Refusing non-https GCP token URL — only https is permitted');
  }
  if (!isGcpOauthHost(parsed.hostname)) {
    throw new GcpEgressError(
      `Refusing GCP token host '${parsed.hostname}' — only ${GCP_OAUTH_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new GcpEgressError('Refusing GCP token URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new GcpEgressError('Refusing GCP token URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  if (path !== '/token') {
    throw new GcpEgressError(
      `Refusing GCP token path '${path}' — only /token on ${GCP_OAUTH_HOST} is permitted`,
    );
  }
  return `https://${GCP_OAUTH_HOST}${path}${parsed.search}`;
}

export function assertGcpProjectId(projectId: string): string {
  if (!GCP_PROJECT_ID_RE.test(projectId)) {
    throw new GcpEgressError(
      `Refusing GCP projectId '${projectId}' — not a valid GCP project identifier`,
    );
  }
  return projectId;
}

export function assertGcpLocationId(location: string): string {
  if (!GCP_LOCATION_ID_RE.test(location)) {
    throw new GcpEgressError(
      `Refusing GCP location '${location}' — not a valid Artifact Registry location identifier`,
    );
  }
  return location;
}

export function assertGcrRepositoryId(repository: string): string {
  if (!GCR_REPOSITORY_ID_RE.test(repository)) {
    throw new GcpEgressError(
      `Refusing Artifact Registry repository '${repository}' — not a valid repository identifier`,
    );
  }
  return repository;
}

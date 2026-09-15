/**
 * Container-scan egress allowlist. Layer pull talks to `ghcr.io` (GHCR),
 * AWS ECR API + `*.dkr.ecr.{region}.amazonaws.com` (ECR digest identities),
 * or `{location}-docker.pkg.dev` (GCR / Artifact Registry digest identities).
 * HTTPS/443 only. Tenant config/body/query/options cannot set a registry host.
 * Identity is a content digest — never a tag, never Docker Hub / ACR / Quay.
 * Location / project / repository are ids; the docker host is derived.
 */

import { AWS_API_SUFFIX, AWS_REGION_RE, AwsEgressError, allowlistedAwsUrl } from './aws.egress';
import {
  GCP_LOCATION_ID_RE,
  GCP_PROJECT_ID_RE,
  GCP_STORAGE_HOST,
  GCR_REPOSITORY_ID_RE,
  GcpEgressError,
  assertGcpLocationId,
  assertGcpProjectId,
  assertGcrRepositoryId,
} from './gcp.egress';

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

/** Keys a tenant might use to point the pull at a non-allowlisted registry. */
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
  'awsEndpoint',
  'ecrHost',
  'ecrEndpoint',
  'dkrHost',
  'dkrUrl',
  'proxyEndpoint',
  'gcrHost',
  'gcrEndpoint',
  'gcrIo',
  'pkgDevHost',
  'pkgDevUrl',
  'artifactRegistryUrl',
  'artifactRegistryHost',
  'arUrl',
  'arHost',
  'dockerUrl',
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
        `Refusing tenant-writable container registry endpoint (${key}) — pulls are ghcr.io / ECR / Artifact Registry digest only, not tenant-configurable`,
      );
    }
  }
  const owner = config.owner;
  if (typeof owner === 'string' && /^https?:\/\//i.test(owner.trim())) {
    throw new ContainerEgressError(
      "Refusing tenant-writable container registry endpoint (owner) — pulls are ghcr.io / ECR / Artifact Registry digest only, not tenant-configurable",
    );
  }
  const region = config.region;
  if (typeof region === 'string' && /^https?:\/\//i.test(region.trim())) {
    throw new ContainerEgressError(
      "Refusing tenant-writable container registry endpoint (region) — region is an id, not a host",
    );
  }
  const regions = config.regions;
  if (Array.isArray(regions)) {
    for (const item of regions) {
      if (typeof item === 'string' && /^https?:\/\//i.test(item.trim())) {
        throw new ContainerEgressError(
          "Refusing tenant-writable container registry endpoint (regions) — region is an id, not a host",
        );
      }
    }
  }
  const location = config.location;
  if (typeof location === 'string' && (/^https?:\/\//i.test(location.trim()) || /pkg\.dev/i.test(location))) {
    throw new ContainerEgressError(
      "Refusing tenant-writable container registry endpoint (location) — location is an id, not a host",
    );
  }
  const locations = config.locations;
  if (Array.isArray(locations)) {
    for (const item of locations) {
      if (typeof item === 'string' && (/^https?:\/\//i.test(item.trim()) || /pkg\.dev/i.test(item))) {
        throw new ContainerEgressError(
          "Refusing tenant-writable container registry endpoint (locations) — location is an id, not a host",
        );
      }
    }
  }
  const projectId = config.projectId;
  if (typeof projectId === 'string' && (/^https?:\/\//i.test(projectId.trim()) || /pkg\.dev/i.test(projectId))) {
    throw new ContainerEgressError(
      "Refusing tenant-writable container registry endpoint (projectId) — project is an id, not a host",
    );
  }
}

export const AWS_ACCOUNT_RE = /^\d{12}$/;

/**
 * `api.ecr.{region}.amazonaws.com` only. Used for GetAuthorizationToken.
 * Region is an id; the host is derived, never tenant-supplied.
 */
export function isEcrApiHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const match = host.match(/^api\.ecr\.([a-z0-9-]+)\.amazonaws\.com$/);
  if (!match) return false;
  return AWS_REGION_RE.test(match[1]!);
}

/**
 * `{accountId}.dkr.ecr.{region}.amazonaws.com` — OCI manifest/blob host.
 * Optional account/region pins the host to this pull's identity.
 */
export function isEcrRegistryHost(
  hostname: string,
  accountId?: string,
  region?: string,
): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const match = host.match(/^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$/);
  if (!match) return false;
  if (!AWS_REGION_RE.test(match[2]!)) return false;
  if (accountId && match[1] !== accountId) return false;
  if (region && match[2] !== region) return false;
  return true;
}

/**
 * ECR serves layer blobs via a 302 to regional S3 (pre-signed). Follow only
 * path-style / virtual-hosted S3 on amazonaws.com for this region — never
 * attach the ECR Basic token or AWS_* keys.
 */
const AWS_BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

export function isEcrBlobS3Host(hostname: string, region: string): boolean {
  if (!AWS_REGION_RE.test(region)) return false;
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === `s3.${AWS_API_SUFFIX}` || host === `s3.${region}.${AWS_API_SUFFIX}`) return true;
  if (host.endsWith(`.s3.${region}.${AWS_API_SUFFIX}`)) {
    const bucket = host.slice(0, -`.s3.${region}.${AWS_API_SUFFIX}`.length);
    return AWS_BUCKET_RE.test(bucket);
  }
  if (host.endsWith(`.s3.${AWS_API_SUFFIX}`)) {
    const bucket = host.slice(0, -`.s3.${AWS_API_SUFFIX}`.length);
    return AWS_BUCKET_RE.test(bucket);
  }
  return false;
}

function wrapAws(fn: () => string): string {
  try {
    return fn();
  } catch (err) {
    if (err instanceof AwsEgressError) {
      throw new ContainerEgressError(err.message);
    }
    throw err;
  }
}

/** Canonicalize GetAuthorizationToken URL. Throws rather than leaking AWS_* keys. */
export function allowlistedEcrApiUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ContainerEgressError('Refusing unparseable ECR API URL');
  }
  const canonical = wrapAws(() => allowlistedAwsUrl(raw));
  if (!isEcrApiHost(parsed.hostname)) {
    throw new ContainerEgressError(
      `Refusing ECR API host '${parsed.hostname}' — only api.ecr.{region}.${AWS_API_SUFFIX} is allowlisted`,
    );
  }
  return canonical;
}

export function ecrApiUrl(region: string): string {
  if (!AWS_REGION_RE.test(region)) {
    throw new ContainerEgressError(`Refusing AWS region '${region}' — not a valid AWS region identifier`);
  }
  return allowlistedEcrApiUrl(`https://api.ecr.${region}.${AWS_API_SUFFIX}/`);
}

export function ecrRegistryHost(accountId: string, region: string): string {
  if (!AWS_ACCOUNT_RE.test(accountId)) {
    throw new ContainerEgressError(`Refusing ECR account '${accountId}' — not a 12-digit account id`);
  }
  if (!AWS_REGION_RE.test(region)) {
    throw new ContainerEgressError(`Refusing AWS region '${region}' — not a valid AWS region identifier`);
  }
  return `${accountId}.dkr.ecr.${region}.${AWS_API_SUFFIX}`;
}

export function allowlistedEcrRegistryUrl(raw: string, accountId: string, region: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ContainerEgressError('Refusing unparseable ECR registry URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new ContainerEgressError('Refusing non-https ECR registry URL — only https is permitted');
  }
  if (parsed.port && parsed.port !== '443') {
    throw new ContainerEgressError('Refusing ECR registry URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new ContainerEgressError('Refusing ECR registry URL that embeds userinfo');
  }
  const expected = ecrRegistryHost(accountId, region);
  if (!isEcrRegistryHost(parsed.hostname, accountId, region)) {
    throw new ContainerEgressError(
      `Refusing ECR registry host '${parsed.hostname}' — only ${expected} is allowlisted for this digest`,
    );
  }
  const path = parsed.pathname || '/';
  if (!path.startsWith('/v2/')) {
    throw new ContainerEgressError(
      `Refusing ECR registry path '${path}' — only /v2/ on ${expected} is permitted`,
    );
  }
  return `https://${expected}${path}${parsed.search}`;
}

/**
 * Blob GET on dkr.ecr may 302 to regional S3. Follow only that host family
 * (HTTPS/443, no userinfo) and never attach the ECR Basic token.
 */
export function allowlistedEcrBlobRedirect(
  raw: string,
  accountId: string,
  region: string,
): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ContainerEgressError('Refusing unparseable ECR blob redirect');
  }
  if (parsed.protocol !== 'https:') {
    throw new ContainerEgressError('Refusing non-https ECR blob redirect');
  }
  if (parsed.port && parsed.port !== '443') {
    throw new ContainerEgressError('Refusing ECR blob redirect with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new ContainerEgressError('Refusing ECR blob redirect that embeds userinfo');
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (isEcrRegistryHost(host, accountId, region)) {
    return allowlistedEcrRegistryUrl(raw, accountId, region);
  }
  if (isEcrBlobS3Host(host, region)) {
    return `https://${host}${parsed.pathname}${parsed.search}`;
  }
  throw new ContainerEgressError(
    `Refusing ECR blob redirect host '${parsed.hostname}' — only ${ecrRegistryHost(accountId, region)} and regional S3 are allowlisted`,
  );
}

function encodeEcrRepoPath(repositoryName: string): string {
  return repositoryName.split('/').map(encodeURIComponent).join('/');
}

export function ecrManifestUrl(
  accountId: string,
  region: string,
  repositoryName: string,
  digest: string,
): string {
  const host = ecrRegistryHost(accountId, region);
  return allowlistedEcrRegistryUrl(
    `https://${host}/v2/${encodeEcrRepoPath(repositoryName)}/manifests/${digest}`,
    accountId,
    region,
  );
}

export function ecrBlobUrl(
  accountId: string,
  region: string,
  repositoryName: string,
  digest: string,
): string {
  const host = ecrRegistryHost(accountId, region);
  return allowlistedEcrRegistryUrl(
    `https://${host}/v2/${encodeEcrRepoPath(repositoryName)}/blobs/${digest}`,
    accountId,
    region,
  );
}

/**
 * `{location}-docker.pkg.dev` — Artifact Registry docker host derived from
 * the inventory location id. Pin the exact host for this pull; never a
 * tenant `pkg.dev` URL or suffix-confused lookalike.
 */
export function gcrRegistryHost(location: string): string {
  const id = wrapGcp(() => assertGcpLocationId(location));
  return `${id}-docker.pkg.dev`;
}

export function isGcrRegistryHost(hostname: string, location?: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const match = host.match(/^([a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)-docker\.pkg\.dev$/);
  if (!match) return false;
  if (!GCP_LOCATION_ID_RE.test(match[1]!)) return false;
  if (location && match[1] !== location) return false;
  return true;
}

/**
 * Artifact Registry may 302 layer blobs to path-style Cloud Storage (same
 * class as ECR → regional S3). Follow only exact `storage.googleapis.com`
 * — never `{bucket}.storage.googleapis.com`, never attach the AR token.
 */
export function isGcrBlobGcsHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === GCP_STORAGE_HOST;
}

function wrapGcp<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    if (err instanceof GcpEgressError) {
      throw new ContainerEgressError(err.message);
    }
    throw err;
  }
}

export function allowlistedGcrRegistryUrl(raw: string, location: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ContainerEgressError('Refusing unparseable Artifact Registry docker URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new ContainerEgressError('Refusing non-https Artifact Registry docker URL — only https is permitted');
  }
  if (parsed.port && parsed.port !== '443') {
    throw new ContainerEgressError('Refusing Artifact Registry docker URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new ContainerEgressError('Refusing Artifact Registry docker URL that embeds userinfo');
  }
  const expected = gcrRegistryHost(location);
  if (!isGcrRegistryHost(parsed.hostname, location)) {
    throw new ContainerEgressError(
      `Refusing Artifact Registry docker host '${parsed.hostname}' — only ${expected} is allowlisted for this digest`,
    );
  }
  const path = parsed.pathname || '/';
  if (!path.startsWith('/v2/')) {
    throw new ContainerEgressError(
      `Refusing Artifact Registry docker path '${path}' — only /v2/ on ${expected} is permitted`,
    );
  }
  return `https://${expected}${path}${parsed.search}`;
}

/**
 * Blob GET on `{location}-docker.pkg.dev` may 302 to path-style GCS.
 * Follow only that host (HTTPS/443, no userinfo) and never attach the
 * Artifact Registry bearer.
 */
export function allowlistedGcrBlobRedirect(raw: string, location: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ContainerEgressError('Refusing unparseable Artifact Registry blob redirect');
  }
  if (parsed.protocol !== 'https:') {
    throw new ContainerEgressError('Refusing non-https Artifact Registry blob redirect');
  }
  if (parsed.port && parsed.port !== '443') {
    throw new ContainerEgressError('Refusing Artifact Registry blob redirect with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new ContainerEgressError('Refusing Artifact Registry blob redirect that embeds userinfo');
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (isGcrRegistryHost(host, location)) {
    return allowlistedGcrRegistryUrl(raw, location);
  }
  if (isGcrBlobGcsHost(host)) {
    return `https://${GCP_STORAGE_HOST}${parsed.pathname}${parsed.search}`;
  }
  throw new ContainerEgressError(
    `Refusing Artifact Registry blob redirect host '${parsed.hostname}' — only ${gcrRegistryHost(location)} and ${GCP_STORAGE_HOST} are allowlisted`,
  );
}

function encodeGcrRepoPath(projectId: string, repository: string, image: string): string {
  wrapGcp(() => assertGcpProjectId(projectId));
  wrapGcp(() => assertGcrRepositoryId(repository));
  if (!image || /^https?:\/\//i.test(image) || image.includes('@')) {
    throw new ContainerEgressError(
      "Refusing Artifact Registry image path — image is a path id, not a registry host",
    );
  }
  return [projectId, repository, ...image.split('/')].map(encodeURIComponent).join('/');
}

function gcrDockerRepository(projectId: string, repository: string, image: string): string {
  wrapGcp(() => assertGcpProjectId(projectId));
  wrapGcp(() => assertGcrRepositoryId(repository));
  return `${projectId}/${repository}/${image}`;
}

export function gcrTokenUrl(
  location: string,
  projectId: string,
  repository: string,
  image: string,
): string {
  const host = gcrRegistryHost(location);
  const repo = gcrDockerRepository(projectId, repository, image);
  return allowlistedGcrRegistryUrl(
    `https://${host}/v2/token?service=${encodeURIComponent(host)}&scope=${encodeURIComponent(`repository:${repo}:pull`)}`,
    location,
  );
}

export function gcrManifestUrl(
  location: string,
  projectId: string,
  repository: string,
  image: string,
  digest: string,
): string {
  const host = gcrRegistryHost(location);
  return allowlistedGcrRegistryUrl(
    `https://${host}/v2/${encodeGcrRepoPath(projectId, repository, image)}/manifests/${digest}`,
    location,
  );
}

export function gcrBlobUrl(
  location: string,
  projectId: string,
  repository: string,
  image: string,
  digest: string,
): string {
  const host = gcrRegistryHost(location);
  return allowlistedGcrRegistryUrl(
    `https://${host}/v2/${encodeGcrRepoPath(projectId, repository, image)}/blobs/${digest}`,
    location,
  );
}

export { GCP_LOCATION_ID_RE, GCP_PROJECT_ID_RE, GCR_REPOSITORY_ID_RE, GCP_STORAGE_HOST };


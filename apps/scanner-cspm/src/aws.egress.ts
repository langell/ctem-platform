/**
 * AWS API egress allowlist. Hosts are AWS's (`*.amazonaws.com`), never
 * tenant-writable. Same hosts as AWS discovery — a config/body/query
 * endpoint must not become the destination for `AWS_*` signing keys.
 */

export const AWS_API_SUFFIX = 'amazonaws.com';

/**
 * Commercial + GovCloud region ids. China (`cn-*`, `amazonaws.com.cn`) is
 * out of scope — that host is not on this allowlist.
 */
export const AWS_REGION_RE =
  /^(af|ap|ca|eu|il|me|mx|sa|us)-(gov-)?(central|east|west|north|south|northeast|northwest|southeast|southwest)-\d+$/;

export class AwsEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AwsEgressError';
  }
}

/** Keys a tenant might use to point discovery at a non-AWS host. */
export const TENANT_ENDPOINT_KEYS = [
  'endpoint',
  'apiUrl',
  'apiEndpoint',
  'host',
  'baseUrl',
  'url',
  'endpointUrl',
  'awsEndpoint',
  'customEndpoint',
] as const;

export function isAwsApiHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === AWS_API_SUFFIX) return true;
  if (!host.endsWith(`.${AWS_API_SUFFIX}`)) return false;
  const labels = host.split('.');
  return labels.at(-2) === 'amazonaws' && labels.at(-1) === 'com';
}

/**
 * Canonicalize and allowlist an AWS API URL. Throws rather than returning a
 * host we must not send keys to.
 */
export function allowlistedAwsUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new AwsEgressError('Refusing unparseable AWS API URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new AwsEgressError(
      `Refusing non-https AWS API URL — only https://*.${AWS_API_SUFFIX} is permitted`,
    );
  }
  if (!isAwsApiHost(parsed.hostname)) {
    throw new AwsEgressError(
      `Refusing AWS API host '${parsed.hostname}' — only ${AWS_API_SUFFIX} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new AwsEgressError('Refusing AWS API URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new AwsEgressError('Refusing AWS API URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  return `https://${parsed.hostname.toLowerCase()}${path}${parsed.search}`;
}

export type AwsService = 'ec2' | 'sts' | 's3' | 'ecr';

/**
 * S3 bucket names are identifiers in a path, never a host. Virtual-hosted
 * `{bucket}.s3.amazonaws.com` is refused so a crafted name cannot pick the
 * destination. Path-style on s3.amazonaws.com / s3.{region}.amazonaws.com only.
 */
export const AWS_BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
export const AWS_SECURITY_GROUP_RE = /^sg-[0-9a-f]{8,17}$/i;

export function assertAwsBucketName(bucket: string): string {
  if (/^https?:\/\//i.test(bucket) || bucket.includes('/') || !AWS_BUCKET_RE.test(bucket)) {
    throw new AwsEgressError(
      `Refusing AWS bucket '${bucket}' — not a valid S3 bucket identifier`,
    );
  }
  return bucket;
}

export function assertAwsSecurityGroupId(groupId: string): string {
  if (/^https?:\/\//i.test(groupId) || !AWS_SECURITY_GROUP_RE.test(groupId)) {
    throw new AwsEgressError(
      `Refusing AWS security group '${groupId}' — not a valid security group identifier`,
    );
  }
  return groupId;
}

/**
 * Path-style S3 object/bucket URL on the allowlisted API host. Query keys
 * with empty values become subresources (`?acl`, `?policyStatus`).
 */
export function awsS3BucketUrl(
  region: string,
  bucket: string,
  query: Record<string, string> = {},
): string {
  if (!AWS_REGION_RE.test(region)) {
    throw new AwsEgressError(`Refusing AWS region '${region}' — not a valid AWS region identifier`);
  }
  assertAwsBucketName(bucket);
  const host = region === 'us-east-1' ? `s3.${AWS_API_SUFFIX}` : `s3.${region}.${AWS_API_SUFFIX}`;
  const parts = Object.entries(query).map(([k, v]) =>
    v === '' ? encodeURIComponent(k) : `${encodeURIComponent(k)}=${encodeURIComponent(v)}`,
  );
  const search = parts.length ? `?${parts.join('&')}` : '';
  return allowlistedAwsUrl(`https://${host}/${encodeURIComponent(bucket)}${search}`);
}

/** Build the platform host for a service. Region is an id, never a host. */
export function awsServiceUrl(service: AwsService, region: string): string {
  if (!AWS_REGION_RE.test(region)) {
    throw new AwsEgressError(`Refusing AWS region '${region}' — not a valid AWS region identifier`);
  }
  // S3 ListBuckets is the account-global API. Always s3.amazonaws.com —
  // never a tenant-derived bucket/website host.
  if (service === 's3') {
    return allowlistedAwsUrl('https://s3.amazonaws.com/');
  }
  // ECR JSON API is api.ecr.{region}.amazonaws.com — never dkr.ecr (layer pull).
  if (service === 'ecr') {
    return allowlistedAwsUrl(`https://api.ecr.${region}.${AWS_API_SUFFIX}/`);
  }
  return allowlistedAwsUrl(`https://${service}.${region}.${AWS_API_SUFFIX}/`);
}

/**
 * Tenant-writable integration config (and body/query-shaped keys) must never
 * choose the AWS API host. Region is allowed; it is not an endpoint.
 */
export function refuseTenantWritableEndpoint(config: Record<string, unknown>): void {
  for (const key of TENANT_ENDPOINT_KEYS) {
    const value = config[key];
    if (value != null && value !== '') {
      throw new AwsEgressError(
        `Refusing tenant-writable AWS endpoint (${key}) — API hosts are AWS's, not tenant-configurable`,
      );
    }
  }
  const region = config.region;
  if (typeof region === 'string' && /^https?:\/\//i.test(region.trim())) {
    throw new AwsEgressError(
      "Refusing tenant-writable AWS endpoint (region) — API hosts are AWS's, not tenant-configurable",
    );
  }
}

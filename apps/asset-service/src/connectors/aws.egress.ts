/**
 * AWS API egress allowlist. Hosts are AWS's (`*.amazonaws.com`), never
 * tenant-writable. A config/body/query endpoint must not become the
 * destination for `AWS_*` signing keys.
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

export type AwsService = 'ec2' | 'sts' | 's3';

/** Build the platform host for a service. Region is an id, never a host. */
export function awsServiceUrl(service: AwsService, region: string): string {
  if (!AWS_REGION_RE.test(region)) {
    throw new AwsEgressError(
      `Refusing AWS region '${region}' — not a valid AWS region identifier`,
    );
  }
  // S3 ListBuckets is the account-global API. Always s3.amazonaws.com —
  // never a tenant-derived bucket/website host.
  if (service === 's3') {
    return allowlistedAwsUrl('https://s3.amazonaws.com/');
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

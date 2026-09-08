/**
 * ECR inventory egress allowlist. Listing talks to AWS's ECR JSON API on
 * `api.ecr.{region}.amazonaws.com` (HTTPS/443) plus STS GetCallerIdentity on
 * `sts.{region}.amazonaws.com`. Never `*.dkr.ecr.*` — that host is for
 * layer/blob pull, which this slice does not do. Tenant config/body/query
 * cannot set a registry or API host.
 *
 * Commercial + GovCloud region ids reuse `AWS_REGION_RE` from aws.egress.
 * China (`cn-*`, `amazonaws.com.cn`) is out of scope.
 */

import { AWS_API_SUFFIX, AWS_REGION_RE, allowlistedAwsUrl, awsServiceUrl } from './aws.egress';

export class EcrEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EcrEgressError';
  }
}

/** Keys a tenant might use to point discovery at a non-ECR API host. */
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
  'apiHost',
  'registryUrl',
  'registryHost',
  'registry',
  'ecrUrl',
  'ecrHost',
  'ecrEndpoint',
  'dockerHost',
  'dkrHost',
] as const;

/**
 * `api.ecr.{region}.amazonaws.com` only. `*.dkr.ecr.*` is the OCI pull host
 * and is not allowlisted for this connector even though it is amazonaws.com.
 */
export function isEcrApiHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const match = host.match(/^api\.ecr\.([a-z0-9-]+)\.amazonaws\.com$/);
  if (!match) return false;
  return AWS_REGION_RE.test(match[1]!);
}

/**
 * Canonicalize and allowlist an ECR JSON API URL. Throws rather than
 * returning a host we must not send AWS_* keys to (including dkr.ecr).
 */
export function allowlistedEcrApiUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new EcrEgressError('Refusing unparseable ECR API URL');
  }
  // amazonaws.com first (commercial + GovCloud), then the ECR API host shape.
  const canonical = allowlistedAwsUrl(raw);
  if (!isEcrApiHost(parsed.hostname)) {
    throw new EcrEgressError(
      `Refusing ECR API host '${parsed.hostname}' — only api.ecr.{region}.${AWS_API_SUFFIX} is allowlisted`,
    );
  }
  return canonical;
}

/** Platform host for DescribeRepositories / DescribeImages. Region is an id. */
export function ecrApiUrl(region: string): string {
  if (!AWS_REGION_RE.test(region)) {
    throw new EcrEgressError(`Refusing AWS region '${region}' — not a valid AWS region identifier`);
  }
  return allowlistedEcrApiUrl(awsServiceUrl('ecr', region));
}

/**
 * Tenant-writable integration config (and body/query-shaped keys) must never
 * choose the ECR API or registry host. Region is allowed; it is not an endpoint.
 */
export function refuseTenantWritableEndpoint(config: Record<string, unknown>): void {
  for (const key of TENANT_ENDPOINT_KEYS) {
    const value = config[key];
    if (value != null && value !== '') {
      throw new EcrEgressError(
        `Refusing tenant-writable ECR endpoint (${key}) — API hosts are AWS's, not tenant-configurable`,
      );
    }
  }
  const region = config.region;
  if (typeof region === 'string' && /^https?:\/\//i.test(region.trim())) {
    throw new EcrEgressError(
      "Refusing tenant-writable ECR endpoint (region) — API hosts are AWS's, not tenant-configurable",
    );
  }
  const regions = config.regions;
  if (Array.isArray(regions)) {
    for (const item of regions) {
      if (typeof item === 'string' && /^https?:\/\//i.test(item.trim())) {
        throw new EcrEgressError(
          "Refusing tenant-writable ECR endpoint (regions) — API hosts are AWS's, not tenant-configurable",
        );
      }
    }
  }
}

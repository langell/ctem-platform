/**
 * AWS API egress primitives for ECR digest pull. Hosts are AWS's
 * (`*.amazonaws.com`), never tenant-writable. Same region-id and
 * `allowlistedAwsUrl` rules as asset-service / CSPM `aws.egress`.
 *
 * GetAuthorizationToken is signed against `api.ecr.{region}.amazonaws.com`.
 * Layer pull uses `*.dkr.ecr.{region}.amazonaws.com` (see container.egress).
 * China (`cn-*`, `amazonaws.com.cn`) is out of scope.
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

export function isAwsApiHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === AWS_API_SUFFIX) return true;
  if (!host.endsWith(`.${AWS_API_SUFFIX}`)) return false;
  const labels = host.split('.');
  return labels.at(-2) === 'amazonaws' && labels.at(-1) === 'com';
}

/**
 * Canonicalize and allowlist an AWS API URL. Throws rather than returning a
 * host we must not send `AWS_*` keys to.
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

/** SigV4 service id for GetAuthorizationToken. */
export type AwsService = 'ecr';

/** Build the ECR JSON API host. Region is an id, never a host. */
export function awsServiceUrl(service: AwsService, region: string): string {
  if (!AWS_REGION_RE.test(region)) {
    throw new AwsEgressError(`Refusing AWS region '${region}' — not a valid AWS region identifier`);
  }
  if (service === 'ecr') {
    return allowlistedAwsUrl(`https://api.ecr.${region}.${AWS_API_SUFFIX}/`);
  }
  throw new AwsEgressError(`Refusing AWS service '${service}' — not used by container pull`);
}

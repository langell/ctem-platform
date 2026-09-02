/**
 * Azure API egress allowlist. Hosts are Azure's (`login.microsoftonline.com`
 * for tokens, `management.azure.com` for ARM), never tenant-writable. A
 * config/body/query endpoint must not become the destination for `AZURE_*`
 * client secrets.
 */

export const AZURE_LOGIN_HOST = 'login.microsoftonline.com';
export const AZURE_ARM_HOST = 'management.azure.com';
export const AZURE_TOKEN_SCOPE = 'https://management.azure.com/.default';

export const AZURE_COMPUTE_API_VERSION = '2024-07-01';
export const AZURE_STORAGE_API_VERSION = '2023-05-01';
export const AZURE_NETWORK_API_VERSION = '2024-05-01';

/**
 * Entra tenant / Azure subscription ids are GUIDs. This is an identifier,
 * never a host — a URL-shaped value is refused.
 */
export const AZURE_GUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class AzureEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AzureEgressError';
  }
}

/** Keys a tenant might use to point discovery at a non-Azure host. */
export const TENANT_ENDPOINT_KEYS = [
  'endpoint',
  'apiUrl',
  'apiEndpoint',
  'host',
  'baseUrl',
  'url',
  'endpointUrl',
  'customEndpoint',
  'apiHost',
  'loginUrl',
  'tokenUrl',
  'tokenUri',
  'token_uri',
  'armEndpoint',
  'resourceManagerUrl',
  'cloud',
  'environment',
  'authority',
] as const;

export type AzureAllowlistedHost = typeof AZURE_LOGIN_HOST | typeof AZURE_ARM_HOST;

export function isAzureLoginHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === AZURE_LOGIN_HOST;
}

export function isAzureArmHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === AZURE_ARM_HOST;
}

function canonicalizeAzureUrl(raw: string, allowed: AzureAllowlistedHost): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new AzureEgressError('Refusing unparseable Azure API URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new AzureEgressError(
      `Refusing non-https Azure API URL — only https://${allowed} is permitted`,
    );
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (host !== allowed) {
    throw new AzureEgressError(
      `Refusing Azure API host '${parsed.hostname}' — only ${allowed} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new AzureEgressError('Refusing Azure API URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new AzureEgressError('Refusing Azure API URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  return `https://${host}${path}${parsed.search}`;
}

/**
 * Canonicalize and allowlist an Azure login URL. Tokens/secrets never leave
 * login.microsoftonline.com.
 */
export function allowlistedAzureTokenUrl(raw: string): string {
  return canonicalizeAzureUrl(raw, AZURE_LOGIN_HOST);
}

/**
 * Canonicalize and allowlist an ARM URL. nextLink is a full URL — parse and
 * allowlist before GET. Off-allowlist hosts (blob, Graph, custom clouds)
 * fail closed.
 */
export function allowlistedAzureArmUrl(raw: string): string {
  return canonicalizeAzureUrl(raw, AZURE_ARM_HOST);
}

export function assertAzureGuid(value: string, field: 'tenantId' | 'subscriptionId'): string {
  const trimmed = value.trim();
  if (/^https?:\/\//i.test(trimmed) || !AZURE_GUID_RE.test(trimmed)) {
    throw new AzureEgressError(
      `Refusing Azure ${field} '${value}' — not a valid Azure ${field === 'tenantId' ? 'tenant' : 'subscription'} identifier`,
    );
  }
  return trimmed.toLowerCase();
}

/** Token URL. tenantId is a path identifier, never a host. */
export function azureTokenUrl(tenantId: string): string {
  const id = assertAzureGuid(tenantId, 'tenantId');
  return allowlistedAzureTokenUrl(
    `https://${AZURE_LOGIN_HOST}/${encodeURIComponent(id)}/oauth2/v2.0/token`,
  );
}

/** ARM list URL. subscriptionId is a GUID identifier, never a host. */
export function azureArmListUrl(
  subscriptionId: string,
  providerPath: string,
  apiVersion: string,
): string {
  const id = assertAzureGuid(subscriptionId, 'subscriptionId');
  if (!providerPath.startsWith('/providers/')) {
    throw new AzureEgressError('Refusing Azure ARM path that is not a provider list');
  }
  return allowlistedAzureArmUrl(
    `https://${AZURE_ARM_HOST}/subscriptions/${encodeURIComponent(id)}${providerPath}?api-version=${encodeURIComponent(apiVersion)}`,
  );
}

/**
 * Tenant-writable integration config (and body/query-shaped keys) must never
 * choose the Azure API host. subscriptionId is allowed; it is not an endpoint.
 */
export function refuseTenantWritableEndpoint(config: Record<string, unknown>): void {
  for (const key of TENANT_ENDPOINT_KEYS) {
    const value = config[key];
    if (value != null && value !== '') {
      throw new AzureEgressError(
        `Refusing tenant-writable Azure endpoint (${key}) — API hosts are Azure's, not tenant-configurable`,
      );
    }
  }
  const subscriptionId = config.subscriptionId;
  if (typeof subscriptionId === 'string' && /^https?:\/\//i.test(subscriptionId.trim())) {
    throw new AzureEgressError(
      "Refusing tenant-writable Azure endpoint (subscriptionId) — API hosts are Azure's, not tenant-configurable",
    );
  }
}

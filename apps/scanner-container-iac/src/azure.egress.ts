/**
 * Azure token-exchange egress for ACR digest pull. Client credentials are
 * posted only to `login.microsoftonline.com` (HTTPS/443) — the same token
 * host ACR inventory / Azure connectors use. Docker layer pull uses
 * `{registry}.azurecr.io` derived from the inventory identity
 * (see container.egress). Tenant config cannot set a token host or
 * loginServer override.
 */

export const AZURE_LOGIN_HOST = 'login.microsoftonline.com';
export const ACR_LOGIN_SUFFIX = 'azurecr.io';
/**
 * AAD scope for ACR data-plane pull. Token audience string sent to
 * login.microsoftonline.com — never a fetch host.
 */
export const ACR_AAD_SCOPE = 'https://containerregistry.azure.net/.default';

/** Entra tenant / Azure subscription ids are GUIDs — identifiers, never hosts. */
export const AZURE_GUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** ACR registry names are 5–50 alphanumeric characters (public cloud). */
export const ACR_REGISTRY_NAME_RE = /^[a-zA-Z0-9]{5,50}$/;

/**
 * Resource group names are identifiers, never hosts. Azure allows letters,
 * digits, underscore, hyphen, period, and parentheses (1–90).
 */
export const AZURE_RESOURCE_GROUP_RE = /^[-\w._()]{1,90}$/;

/** Repository names are path ids (`team/api`), never registry URLs. */
export const ACR_REPOSITORY_RE =
  /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/;

export class AzureEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AzureEgressError';
  }
}

export function isAzureLoginHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === AZURE_LOGIN_HOST;
}

/**
 * Canonicalize the Azure login token URL. Throws rather than returning a
 * host we must not send AZURE_CLIENT_SECRET to.
 */
export function allowlistedAzureTokenUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new AzureEgressError('Refusing unparseable Azure token URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new AzureEgressError(
      `Refusing non-https Azure token URL — only https://${AZURE_LOGIN_HOST} is permitted`,
    );
  }
  if (!isAzureLoginHost(parsed.hostname)) {
    throw new AzureEgressError(
      `Refusing Azure token host '${parsed.hostname}' — only ${AZURE_LOGIN_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new AzureEgressError('Refusing Azure token URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new AzureEgressError('Refusing Azure token URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  if (!/^\/[0-9a-f-]+\/oauth2\/v2\.0\/token$/i.test(path)) {
    throw new AzureEgressError(
      `Refusing Azure token path '${path}' — only /{tenantId}/oauth2/v2.0/token on ${AZURE_LOGIN_HOST} is permitted`,
    );
  }
  return `https://${AZURE_LOGIN_HOST}${path}${parsed.search}`;
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

export function assertAcrRegistryName(name: string): string {
  const trimmed = name.trim();
  if (/^https?:\/\//i.test(trimmed) || trimmed.includes('.') || !ACR_REGISTRY_NAME_RE.test(trimmed)) {
    throw new AzureEgressError(
      `Refusing ACR registry '${name}' — not a valid Azure Container Registry name`,
    );
  }
  return trimmed.toLowerCase();
}

export function assertAzureResourceGroup(name: string): string {
  const trimmed = name.trim();
  if (
    /^https?:\/\//i.test(trimmed) ||
    /azurecr\.io/i.test(trimmed) ||
    !AZURE_RESOURCE_GROUP_RE.test(trimmed) ||
    trimmed.endsWith('.')
  ) {
    throw new AzureEgressError(
      `Refusing Azure resourceGroup '${name}' — not a valid resource group identifier`,
    );
  }
  return trimmed;
}

export function assertAcrRepository(name: string): string {
  const trimmed = name.trim();
  if (/^https?:\/\//i.test(trimmed) || /azurecr\.io/i.test(trimmed) || !ACR_REPOSITORY_RE.test(trimmed)) {
    throw new AzureEgressError(
      `Refusing ACR repository '${name}' — not a valid repository identifier`,
    );
  }
  return trimmed;
}

/**
 * `{name}.azurecr.io` only — one label plus the public-cloud suffix.
 * Data endpoints (`{name}.{region}.data.azurecr.io`) and lookalikes fail.
 */
export function isAcrLoginServerHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const match = host.match(/^([a-z0-9]{5,50})\.azurecr\.io$/);
  if (!match) return false;
  return ACR_REGISTRY_NAME_RE.test(match[1]!);
}

/**
 * Pin a loginServer attribute to `{registryName}.azurecr.io`. A URL, port,
 * userinfo, or suffix-confused host is refused. The host is never used as
 * a tenant override — it is only a consistency check against the identity.
 */
export function assertAcrLoginServer(registryName: string, loginServer: string): string {
  const name = assertAcrRegistryName(registryName);
  const expected = `${name}.${ACR_LOGIN_SUFFIX}`;
  let host: string;
  const trimmed = loginServer.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    throw new AzureEgressError(
      `Refusing tenant-writable ACR endpoint (loginServer) — loginServer is an ARM-derived hostname, not a tenant URL`,
    );
  }
  host = trimmed.toLowerCase().replace(/\.$/, '').split(':')[0] ?? '';
  if (!isAcrLoginServerHost(host) || host !== expected) {
    throw new AzureEgressError(
      `Refusing ACR loginServer '${loginServer}' — only the identity-derived ${expected} is allowlisted`,
    );
  }
  return host;
}

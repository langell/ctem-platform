/**
 * ACR inventory egress allowlist. Discovery talks to:
 *   - `login.microsoftonline.com` (AAD token; ARM + ACR audiences)
 *   - `management.azure.com` (ARM list of registries)
 *   - the registry's own `{loginServer}` on `*.azurecr.io` (catalog +
 *     manifest-list metadata; HTTPS/443)
 *
 * `{loginServer}` is taken from ARM (`properties.loginServer`) and pinned
 * per request — never a tenant-supplied host, never a lookalike suffix
 * (`foo.azurecr.io.evil.example`), never China/gov (`*.azurecr.cn` /
 * `*.azurecr.us`). Layer/blob pull (`/v2/.../blobs/`, docker CLI) is out.
 */

import {
  AZURE_ARM_HOST,
  AZURE_GUID_RE,
  allowlistedAzureArmUrl,
  azureArmListUrl,
} from './azure.egress';

export const ACR_ARM_API_VERSION = '2023-07-01';
export const ACR_LOGIN_SUFFIX = 'azurecr.io';

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

export class AcrEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AcrEgressError';
  }
}

/**
 * Keys a tenant might use to point discovery at a non-ACR host. `registry`
 * / `resourceGroup` are identifiers and are not in this list.
 */
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
  'loginServer',
  'login_server',
  'tokenUrl',
  'tokenUri',
  'token_uri',
  'armEndpoint',
  'resourceManagerUrl',
  'cloud',
  'environment',
  'authority',
  'registryUrl',
  'registryHost',
  'registryEndpoint',
  'acrUrl',
  'acrHost',
  'acrEndpoint',
  'azurecrUrl',
  'azurecrHost',
  'dockerHost',
  'dockerUrl',
  'containerRegistryUrl',
  'containerRegistryHost',
] as const;

/** GitLab-style extra-host allowlist. ACR refuses this pattern entirely. */
export const EXTRA_HOST_KEY_RE = /^EXTRA_.+_HOST(_KEYS)?$/i;

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

export function assertAcrRegistryName(name: string): string {
  const trimmed = name.trim();
  if (/^https?:\/\//i.test(trimmed) || !ACR_REGISTRY_NAME_RE.test(trimmed)) {
    throw new AcrEgressError(
      `Refusing ACR registry '${name}' — not a valid Azure Container Registry name`,
    );
  }
  return trimmed.toLowerCase();
}

export function assertAzureResourceGroup(name: string): string {
  const trimmed = name.trim();
  if (
    /^https?:\/\//i.test(trimmed) ||
    !AZURE_RESOURCE_GROUP_RE.test(trimmed) ||
    trimmed.endsWith('.')
  ) {
    throw new AcrEgressError(
      `Refusing Azure resourceGroup '${name}' — not a valid resource group identifier`,
    );
  }
  return trimmed;
}

export function assertAcrRepository(name: string): string {
  const trimmed = name.trim();
  if (/^https?:\/\//i.test(trimmed) || !ACR_REPOSITORY_RE.test(trimmed)) {
    throw new AcrEgressError(
      `Refusing ACR repository '${name}' — not a valid repository identifier`,
    );
  }
  return trimmed;
}

/**
 * Pin ARM `properties.loginServer` to `{registryName}.azurecr.io`. A URL,
 * port, userinfo, or suffix-confused host is refused.
 */
export function assertAcrLoginServer(registryName: string, loginServer: string): string {
  const name = assertAcrRegistryName(registryName);
  const expected = `${name}.${ACR_LOGIN_SUFFIX}`;
  let host: string;
  const trimmed = loginServer.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new AcrEgressError('Refusing unparseable ACR loginServer');
    }
    host = parsed.hostname.toLowerCase().replace(/\.$/, '');
    if (parsed.protocol !== 'https:') {
      throw new AcrEgressError(
        `Refusing ACR loginServer '${loginServer}' — only https://${expected} is permitted`,
      );
    }
    if (parsed.port && parsed.port !== '443') {
      throw new AcrEgressError('Refusing ACR loginServer with a non-default port');
    }
    if (parsed.username || parsed.password) {
      throw new AcrEgressError('Refusing ACR loginServer that embeds userinfo');
    }
  } else {
    host = trimmed.toLowerCase().replace(/\.$/, '').split(':')[0] ?? '';
  }
  if (!isAcrLoginServerHost(host) || host !== expected) {
    throw new AcrEgressError(
      `Refusing ACR loginServer '${loginServer}' — only the ARM-derived ${expected} is allowlisted`,
    );
  }
  return host;
}

/**
 * Canonicalize a loginServer that is already a hostname (`{name}.azurecr.io`).
 * Used after ARM has returned the host — not a tenant-supplied URL.
 */
export function pinAcrLoginServer(loginServer: string): string {
  const host = loginServer.trim().toLowerCase().replace(/\.$/, '');
  if (!isAcrLoginServerHost(host)) {
    throw new AcrEgressError(
      `Refusing ACR loginServer '${loginServer}' — only {name}.${ACR_LOGIN_SUFFIX} is allowlisted`,
    );
  }
  const name = host.slice(0, -`.${ACR_LOGIN_SUFFIX}`.length);
  return assertAcrLoginServer(name, host);
}

/**
 * Canonicalize and allowlist an ACR data-plane URL against one ARM-derived
 * loginServer. Any other `*.azurecr.io` (or lookalike) fails closed.
 */
export function allowlistedAcrDataUrl(raw: string, loginServer: string): string {
  const expected = pinAcrLoginServer(loginServer);
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new AcrEgressError('Refusing unparseable ACR data-plane URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new AcrEgressError(`Refusing non-https ACR URL — only https://${expected} is permitted`);
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (!isAcrLoginServerHost(host) || host !== expected) {
    throw new AcrEgressError(
      `Refusing ACR host '${parsed.hostname}' — only the ARM-derived ${expected} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new AcrEgressError('Refusing ACR URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new AcrEgressError('Refusing ACR URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  return `https://${host}${path}${parsed.search}`;
}

function encodeRepositoryPath(repository: string): string {
  return assertAcrRepository(repository)
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
}

export function acrOauthExchangeUrl(loginServer: string): string {
  const host = pinAcrLoginServer(loginServer);
  return allowlistedAcrDataUrl(`https://${host}/oauth2/exchange`, host);
}

export function acrOauthTokenUrl(loginServer: string): string {
  const host = pinAcrLoginServer(loginServer);
  return allowlistedAcrDataUrl(`https://${host}/oauth2/token`, host);
}

export function acrCatalogUrl(loginServer: string, last?: string): string {
  const host = pinAcrLoginServer(loginServer);
  const url = new URL(`https://${host}/acr/v1/_catalog`);
  url.searchParams.set('n', '100');
  if (last) url.searchParams.set('last', last);
  return allowlistedAcrDataUrl(url.href, host);
}

export function acrManifestsUrl(loginServer: string, repository: string, last?: string): string {
  const host = pinAcrLoginServer(loginServer);
  const url = new URL(`https://${host}/acr/v1/${encodeRepositoryPath(repository)}/_manifests`);
  url.searchParams.set('n', '100');
  if (last) url.searchParams.set('last', last);
  return allowlistedAcrDataUrl(url.href, host);
}

/** ARM list of Container Registries. subscriptionId / resourceGroup are ids. */
export function acrArmRegistriesUrl(subscriptionId: string, resourceGroup?: string): string {
  const id = subscriptionId.trim();
  if (/^https?:\/\//i.test(id) || !AZURE_GUID_RE.test(id)) {
    throw new AcrEgressError(
      `Refusing Azure subscriptionId '${subscriptionId}' — not a valid Azure subscription identifier`,
    );
  }
  if (resourceGroup) {
    const rg = assertAzureResourceGroup(resourceGroup);
    return allowlistedAzureArmUrl(
      `https://${AZURE_ARM_HOST}/subscriptions/${encodeURIComponent(id.toLowerCase())}/resourceGroups/${encodeURIComponent(rg)}/providers/Microsoft.ContainerRegistry/registries?api-version=${encodeURIComponent(ACR_ARM_API_VERSION)}`,
    );
  }
  return allowlistedAzureArmUrl(
    azureArmListUrl(id, '/providers/Microsoft.ContainerRegistry/registries', ACR_ARM_API_VERSION),
  );
}

/** Complete-signal is Link rel=next (often a relative `/acr/v1/...` href). */
export function nextRelFromLinkHeader(link: string | null | undefined): string | undefined {
  if (!link || typeof link !== 'string') return undefined;
  for (const part of link.split(',')) {
    const match = part.match(/<([^>]+)>\s*;\s*rel\s*=\s*"?next"?/i);
    const href = match?.[1]?.trim();
    if (href) return href;
  }
  return undefined;
}

/**
 * Resolve a catalog/manifest `rel=next` against the pinned loginServer.
 * Relative hrefs stay on that host; an absolute URL is allowlisted to it.
 */
export function allowlistedAcrNextUrl(href: string, loginServer: string): string {
  const host = pinAcrLoginServer(loginServer);
  const trimmed = href.trim();
  if (!trimmed) {
    throw new AcrEgressError('Refusing empty ACR continuation URL');
  }
  if (/^https?:\/\//i.test(trimmed)) {
    return allowlistedAcrDataUrl(trimmed, host);
  }
  if (trimmed.startsWith('/')) {
    return allowlistedAcrDataUrl(`https://${host}${trimmed}`, host);
  }
  throw new AcrEgressError(
    'Refusing ACR continuation that is not an absolute or root-relative URL',
  );
}

function valueIsSet(value: unknown): boolean {
  return value != null && value !== '';
}

function refuseIfUrl(value: unknown, field: string): void {
  if (typeof value === 'string' && /^https?:\/\//i.test(value.trim())) {
    throw new AcrEgressError(
      `Refusing tenant-writable ACR endpoint (${field}) — API hosts are Azure's, not tenant-configurable`,
    );
  }
}

/**
 * Tenant-writable integration config must never choose the ARM / AAD / ACR
 * host. subscriptionId, resourceGroup, and registry name are identifiers.
 */
export function refuseTenantWritableEndpoint(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (EXTRA_HOST_KEY_RE.test(key) && valueIsSet(config[key])) {
      throw new AcrEgressError(
        `Refusing tenant-writable ACR endpoint (${key}) — EXTRA_*_HOST_KEYS is not permitted`,
      );
    }
  }
  for (const key of TENANT_ENDPOINT_KEYS) {
    if (valueIsSet(config[key])) {
      throw new AcrEgressError(
        `Refusing tenant-writable ACR endpoint (${key}) — API hosts are Azure's, not tenant-configurable`,
      );
    }
  }
  refuseIfUrl(config.subscriptionId, 'subscriptionId');
  refuseIfUrl(config.resourceGroup, 'resourceGroup');
  refuseIfUrl(config.registry, 'registry');
  refuseIfUrl(config.registryName, 'registryName');
  const resourceGroups = config.resourceGroups;
  if (Array.isArray(resourceGroups)) {
    for (const item of resourceGroups) refuseIfUrl(item, 'resourceGroups');
  }
  const registries = config.registries;
  if (Array.isArray(registries)) {
    for (const item of registries) refuseIfUrl(item, 'registries');
  }
  const repositories = config.repositories;
  if (Array.isArray(repositories)) {
    for (const item of repositories) refuseIfUrl(item, 'repositories');
  }
}

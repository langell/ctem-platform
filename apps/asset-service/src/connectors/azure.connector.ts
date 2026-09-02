import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { requireAzureCredentials } from './credentials';
import {
  AZURE_COMPUTE_API_VERSION,
  AZURE_GUID_RE,
  AZURE_NETWORK_API_VERSION,
  AZURE_STORAGE_API_VERSION,
  allowlistedAzureArmUrl,
  azureArmListUrl,
  refuseTenantWritableEndpoint,
} from './azure.egress';
import { exchangeAzureAccessToken } from './azure.token';

export const AzureResourceType = z.enum([
  'virtual_machine',
  'storage_account',
  'nsg',
  'public_ip',
]);
export type AzureResourceType = z.infer<typeof AzureResourceType>;

export const AzureConnectorConfig = z.object({
  /** Subscription to inventory. This is an Azure subscription GUID, not an API host. */
  subscriptionId: z.string().regex(AZURE_GUID_RE, 'must be an Azure subscription identifier'),
  /** Optional allowlist of resource types; omit to inventory the default set. */
  resourceTypes: z.array(AzureResourceType).optional(),
});
export type AzureConnectorConfig = z.infer<typeof AzureConnectorConfig>;

export const AZURE_PER_PAGE = 100;
export const AZURE_MAX_PAGES = 20;

const DEFAULT_RESOURCE_TYPES: AzureResourceType[] = [
  'virtual_machine',
  'storage_account',
  'nsg',
  'public_ip',
];

export interface AzureVirtualMachine {
  name: string;
  resourceGroup: string;
  location?: string;
  provisioningState?: string;
  hasPublicIp: boolean;
}

export interface AzureStorageAccount {
  name: string;
  resourceGroup: string;
  location?: string;
}

export interface AzureNsg {
  name: string;
  resourceGroup: string;
  location?: string;
  internetOpen: boolean;
}

export interface AzurePublicIp {
  name: string;
  resourceGroup: string;
  location?: string;
  ipAddress?: string;
}

export function resourceGroupFromId(id: string | undefined): string | undefined {
  if (!id) return undefined;
  const match = id.match(/\/resourceGroups\/([^/]+)\//i);
  return match?.[1];
}

export function vmToAsset(subscriptionId: string, vm: AzureVirtualMachine): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `azure:${subscriptionId}:vm:${vm.resourceGroup}:${vm.name}`,
    name: vm.name,
    source: 'azure',
    exposure: vm.hasPublicIp ? 'internet_facing' : 'internal',
    attributes: {
      subscriptionId,
      resourceGroup: vm.resourceGroup,
      location: vm.location ?? null,
      resourceType: 'virtual_machine',
      provisioningState: vm.provisioningState ?? null,
    },
  };
}

export function storageAccountToAsset(
  subscriptionId: string,
  account: AzureStorageAccount,
): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `azure:${subscriptionId}:sa:${account.resourceGroup}:${account.name}`,
    name: account.name,
    source: 'azure',
    // Public-blob / network ACLs are CSPM. Inventory does not claim exposure.
    exposure: 'unknown',
    attributes: {
      subscriptionId,
      resourceGroup: account.resourceGroup,
      location: account.location ?? null,
      resourceType: 'storage_account',
    },
  };
}

export function nsgToAsset(subscriptionId: string, nsg: AzureNsg): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `azure:${subscriptionId}:nsg:${nsg.resourceGroup}:${nsg.name}`,
    name: nsg.name,
    source: 'azure',
    exposure: nsg.internetOpen ? 'internet_facing' : 'internal',
    attributes: {
      subscriptionId,
      resourceGroup: nsg.resourceGroup,
      location: nsg.location ?? null,
      resourceType: 'nsg',
    },
  };
}

export function publicIpToAsset(subscriptionId: string, pip: AzurePublicIp): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `azure:${subscriptionId}:pip:${pip.resourceGroup}:${pip.name}`,
    name: pip.ipAddress || pip.name,
    source: 'azure',
    exposure: 'internet_facing',
    attributes: {
      subscriptionId,
      resourceGroup: pip.resourceGroup,
      location: pip.location ?? null,
      resourceType: 'public_ip',
      ipAddress: pip.ipAddress ?? null,
    },
  };
}

/** Complete-signal is a missing nextLink, not page length. */
export function nextLink(json: unknown): string | undefined {
  if (!json || typeof json !== 'object') return undefined;
  const link = (json as { nextLink?: unknown }).nextLink;
  if (typeof link !== 'string') return undefined;
  const trimmed = link.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function listValues(json: unknown): unknown[] {
  const value = json && typeof json === 'object' ? (json as { value?: unknown }).value : undefined;
  return Array.isArray(value) ? value : [];
}

function namedResource(
  raw: unknown,
): { name: string; id: string; resourceGroup: string; location?: string; properties: Record<string, unknown> } | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const item = raw as { name?: unknown; id?: unknown; location?: unknown; properties?: unknown };
  if (typeof item.name !== 'string' || item.name.length === 0) return undefined;
  if (typeof item.id !== 'string') return undefined;
  const resourceGroup = resourceGroupFromId(item.id);
  if (!resourceGroup) return undefined;
  return {
    name: item.name,
    id: item.id,
    resourceGroup,
    location: typeof item.location === 'string' ? item.location : undefined,
    properties: item.properties && typeof item.properties === 'object' ? (item.properties as Record<string, unknown>) : {},
  };
}

function isInternetSource(prefix: string): boolean {
  const p = prefix.trim();
  return p === '*' || p === '0.0.0.0/0' || p.toLowerCase() === 'internet';
}

function sourcePrefixes(props: Record<string, unknown>): string[] {
  const prefixes: string[] = [];
  if (typeof props.sourceAddressPrefix === 'string') prefixes.push(props.sourceAddressPrefix);
  if (Array.isArray(props.sourceAddressPrefixes)) {
    for (const p of props.sourceAddressPrefixes) {
      if (typeof p === 'string') prefixes.push(p);
    }
  }
  return prefixes;
}

function vmHasPublicIp(properties: Record<string, unknown>): boolean {
  const networkProfile = properties.networkProfile;
  if (!networkProfile || typeof networkProfile !== 'object') return false;
  const nics = (networkProfile as { networkInterfaces?: unknown }).networkInterfaces;
  if (!Array.isArray(nics)) return false;
  for (const nic of nics) {
    if (!nic || typeof nic !== 'object') continue;
    const nicProps = (nic as { properties?: unknown }).properties;
    if (!nicProps || typeof nicProps !== 'object') continue;
    const configs = (nicProps as { ipConfigurations?: unknown }).ipConfigurations;
    if (!Array.isArray(configs)) continue;
    for (const cfg of configs) {
      if (!cfg || typeof cfg !== 'object') continue;
      const cfgProps = (cfg as { properties?: unknown }).properties;
      if (!cfgProps || typeof cfgProps !== 'object') continue;
      const pip = (cfgProps as { publicIPAddress?: unknown }).publicIPAddress;
      if (pip && typeof pip === 'object' && typeof (pip as { id?: unknown }).id === 'string') {
        return true;
      }
    }
  }
  return false;
}

export function parseVirtualMachines(json: unknown): AzureVirtualMachine[] {
  const vms: AzureVirtualMachine[] = [];
  for (const raw of listValues(json)) {
    const item = namedResource(raw);
    if (!item) continue;
    vms.push({
      name: item.name,
      resourceGroup: item.resourceGroup,
      location: item.location,
      provisioningState:
        typeof item.properties.provisioningState === 'string'
          ? item.properties.provisioningState
          : undefined,
      hasPublicIp: vmHasPublicIp(item.properties),
    });
  }
  return vms;
}

export function parseStorageAccounts(json: unknown): AzureStorageAccount[] {
  const accounts: AzureStorageAccount[] = [];
  for (const raw of listValues(json)) {
    const item = namedResource(raw);
    if (!item) continue;
    accounts.push({
      name: item.name,
      resourceGroup: item.resourceGroup,
      location: item.location,
    });
  }
  return accounts;
}

export function parseNsgs(json: unknown): AzureNsg[] {
  const nsgs: AzureNsg[] = [];
  for (const raw of listValues(json)) {
    const item = namedResource(raw);
    if (!item) continue;
    const rules = Array.isArray(item.properties.securityRules) ? item.properties.securityRules : [];
    let internetOpen = false;
    for (const rule of rules) {
      if (!rule || typeof rule !== 'object') continue;
      const props = (rule as { properties?: unknown }).properties;
      if (!props || typeof props !== 'object') continue;
      const p = props as Record<string, unknown>;
      const direction = (typeof p.direction === 'string' ? p.direction : '').toLowerCase();
      const access = (typeof p.access === 'string' ? p.access : '').toLowerCase();
      // Inbound Allow from the internet only — egress-open (AllowInternetOutBound) is not exposure.
      if (direction === 'inbound' && access === 'allow' && sourcePrefixes(p).some(isInternetSource)) {
        internetOpen = true;
        break;
      }
    }
    nsgs.push({
      name: item.name,
      resourceGroup: item.resourceGroup,
      location: item.location,
      internetOpen,
    });
  }
  return nsgs;
}

export function parsePublicIps(json: unknown): AzurePublicIp[] {
  const addresses: AzurePublicIp[] = [];
  for (const raw of listValues(json)) {
    const item = namedResource(raw);
    if (!item) continue;
    addresses.push({
      name: item.name,
      resourceGroup: item.resourceGroup,
      location: item.location,
      ipAddress: typeof item.properties.ipAddress === 'string' ? item.properties.ipAddress : undefined,
    });
  }
  return addresses;
}

/**
 * Cloud-resource inventory via Azure ARM. Same persistence path as AWS/GCP:
 * discover → UpsertAssetRequest → scheduler upsert + archiveStale scoped per
 * integrationId.
 *
 * Hosts are hardcoded to allowlisted `login.microsoftonline.com` (token) and
 * `management.azure.com` (ARM). Tenant config/body/query cannot set a custom
 * endpoint. Credentials are platform-operated `env:AZURE_*` and fail closed
 * when missing — there is no public-listing fallback.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — ARM list APIs do
 * not offer a reliable incremental window for this inventory.
 */
@Injectable()
export class AzureConnector implements AssetConnector {
  readonly provider = 'azure';
  readonly assetKinds = ['cloud_resource'];
  private readonly log = rootLogger.child({ component: 'azure-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantWritableEndpoint(ctx.config);
    const config = AzureConnectorConfig.parse(ctx.config);
    const creds = requireAzureCredentials(ctx.credentialRef);
    const accessToken = await exchangeAzureAccessToken(creds);

    const subscriptionId = config.subscriptionId.toLowerCase();
    const allow = new Set(config.resourceTypes?.length ? config.resourceTypes : DEFAULT_RESOURCE_TYPES);
    let seen = 0;

    if (allow.has('virtual_machine')) {
      for await (const asset of this.listVirtualMachines(subscriptionId, accessToken)) {
        seen += 1;
        yield asset;
      }
    }
    if (allow.has('nsg')) {
      for await (const asset of this.listNsgs(subscriptionId, accessToken)) {
        seen += 1;
        yield asset;
      }
    }
    if (allow.has('public_ip')) {
      for await (const asset of this.listPublicIps(subscriptionId, accessToken)) {
        seen += 1;
        yield asset;
      }
    }
    if (allow.has('storage_account')) {
      for await (const asset of this.listStorageAccounts(subscriptionId, accessToken)) {
        seen += 1;
        yield asset;
      }
    }

    this.log.info({ subscriptionId, resources: seen }, 'azure discovery complete');
  }

  private async *listVirtualMachines(
    subscriptionId: string,
    accessToken: string,
  ): AsyncIterable<UpsertAssetRequest> {
    yield* this.pagedGet(
      azureArmListUrl(subscriptionId, '/providers/Microsoft.Compute/virtualMachines', AZURE_COMPUTE_API_VERSION),
      accessToken,
      (json) => parseVirtualMachines(json).map((vm) => vmToAsset(subscriptionId, vm)),
      'virtual machines',
    );
  }

  private async *listNsgs(
    subscriptionId: string,
    accessToken: string,
  ): AsyncIterable<UpsertAssetRequest> {
    yield* this.pagedGet(
      azureArmListUrl(
        subscriptionId,
        '/providers/Microsoft.Network/networkSecurityGroups',
        AZURE_NETWORK_API_VERSION,
      ),
      accessToken,
      (json) => parseNsgs(json).map((n) => nsgToAsset(subscriptionId, n)),
      'NSGs',
    );
  }

  private async *listPublicIps(
    subscriptionId: string,
    accessToken: string,
  ): AsyncIterable<UpsertAssetRequest> {
    yield* this.pagedGet(
      azureArmListUrl(subscriptionId, '/providers/Microsoft.Network/publicIPAddresses', AZURE_NETWORK_API_VERSION),
      accessToken,
      (json) => parsePublicIps(json).map((p) => publicIpToAsset(subscriptionId, p)),
      'public IPs',
    );
  }

  private async *listStorageAccounts(
    subscriptionId: string,
    accessToken: string,
  ): AsyncIterable<UpsertAssetRequest> {
    yield* this.pagedGet(
      azureArmListUrl(subscriptionId, '/providers/Microsoft.Storage/storageAccounts', AZURE_STORAGE_API_VERSION),
      accessToken,
      (json) => parseStorageAccounts(json).map((a) => storageAccountToAsset(subscriptionId, a)),
      'storage accounts',
    );
  }

  /**
   * Complete-signal is nextLink, not page length. A last page of
   * AZURE_PER_PAGE with no nextLink succeeds. Only a leftover nextLink after
   * the cap is truncated / fail-closed (so archiveStale cannot run on a
   * partial list). nextLink is a full URL — parse and allowlist before GET.
   */
  private async *pagedGet(
    firstUrl: string,
    accessToken: string,
    mapPage: (json: unknown) => UpsertAssetRequest[],
    label: string,
  ): AsyncIterable<UpsertAssetRequest> {
    let url: string | undefined = allowlistedAzureArmUrl(firstUrl);
    for (let page = 1; page <= AZURE_MAX_PAGES; page++) {
      const json = await this.getJson(url, accessToken, label);
      const assets = mapPage(json);
      for (const asset of assets) yield asset;
      const link = nextLink(json);
      if (!link) return;
      url = allowlistedAzureArmUrl(link);
      if (page === AZURE_MAX_PAGES) this.failTruncated(label);
    }
  }

  private failTruncated(label: string): never {
    this.log.error(
      { pages: AZURE_MAX_PAGES, perPage: AZURE_PER_PAGE, label },
      'azure listing truncated at page cap',
    );
    throw new Error(
      `Azure listing truncated at ${AZURE_MAX_PAGES * AZURE_PER_PAGE} ${label} (page cap ${AZURE_MAX_PAGES}); refusing to archive unseen assets`,
    );
  }

  private async getJson(url: string, accessToken: string, label: string): Promise<unknown> {
    // Belt: never send the bearer token off the ARM allowlist even if a caller built `url`.
    allowlistedAzureArmUrl(url);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${accessToken}`,
      },
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new Error(`Azure ${label} API returned ${res.status}`);
    }
    return res.json();
  }
}

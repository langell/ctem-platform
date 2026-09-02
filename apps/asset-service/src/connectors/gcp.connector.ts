import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { requireGcpCredentials } from './credentials';
import {
  GCP_PROJECT_ID_RE,
  allowlistedGcpUrl,
  gcpComputeUrl,
  gcpStorageBucketsUrl,
  refuseTenantWritableEndpoint,
} from './gcp.egress';
import { exchangeGcpAccessToken } from './gcp.jwt';

export const GcpResourceType = z.enum([
  'gce_instance',
  'gcs_bucket',
  'firewall',
  'external_ip',
]);
export type GcpResourceType = z.infer<typeof GcpResourceType>;

export const GcpConnectorConfig = z.object({
  /** Project to inventory. This is a GCP project id, not an API host. */
  projectId: z.string().regex(GCP_PROJECT_ID_RE, 'must be a GCP project identifier'),
  /** Optional allowlist of resource types; omit to inventory the default set. */
  resourceTypes: z.array(GcpResourceType).optional(),
});
export type GcpConnectorConfig = z.infer<typeof GcpConnectorConfig>;

export const GCP_PER_PAGE = 100;
export const GCP_MAX_PAGES = 20;

const DEFAULT_RESOURCE_TYPES: GcpResourceType[] = [
  'gce_instance',
  'gcs_bucket',
  'firewall',
  'external_ip',
];

export interface GcpInstance {
  name: string;
  zone: string;
  status?: string;
  natIp?: string;
  networkIp?: string;
}

export interface GcpFirewall {
  name: string;
  internetOpen: boolean;
}

export interface GcpExternalIp {
  name: string;
  region: string;
  address: string;
  status?: string;
  instance?: string;
}

export interface GcpBucket {
  name: string;
  location?: string;
  timeCreated?: string;
}

export function lastPathSegment(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const parts = value.split('/').filter(Boolean);
  return parts.at(-1);
}

export function instanceToAsset(projectId: string, instance: GcpInstance): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `gcp:${projectId}:gce:${instance.zone}:${instance.name}`,
    name: instance.name,
    source: 'gcp',
    exposure: instance.natIp ? 'internet_facing' : 'internal',
    attributes: {
      projectId,
      zone: instance.zone,
      resourceType: 'gce_instance',
      status: instance.status ?? null,
      natIp: instance.natIp ?? null,
      networkIp: instance.networkIp ?? null,
    },
  };
}

export function firewallToAsset(projectId: string, firewall: GcpFirewall): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `gcp:${projectId}:fw:${firewall.name}`,
    name: firewall.name,
    source: 'gcp',
    exposure: firewall.internetOpen ? 'internet_facing' : 'internal',
    attributes: {
      projectId,
      resourceType: 'firewall',
    },
  };
}

export function externalIpToAsset(projectId: string, address: GcpExternalIp): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `gcp:${projectId}:ip:${address.region}:${address.name}`,
    name: address.address,
    source: 'gcp',
    exposure: 'internet_facing',
    attributes: {
      projectId,
      region: address.region,
      resourceType: 'external_ip',
      address: address.address,
      status: address.status ?? null,
      instance: address.instance ?? null,
    },
  };
}

export function bucketToAsset(projectId: string, bucket: GcpBucket): UpsertAssetRequest {
  return {
    kind: 'cloud_resource',
    externalKey: `gcp:${projectId}:gcs:${bucket.name}`,
    name: bucket.name,
    source: 'gcp',
    // Bucket IAM / ACLs are CSPM. Inventory does not claim exposure.
    exposure: 'unknown',
    attributes: {
      projectId,
      resourceType: 'gcs_bucket',
      location: bucket.location ?? null,
      timeCreated: bucket.timeCreated ?? null,
    },
  };
}

export function nextPageToken(json: unknown): string | undefined {
  if (!json || typeof json !== 'object') return undefined;
  const token = (json as { nextPageToken?: unknown }).nextPageToken;
  if (typeof token !== 'string') return undefined;
  const trimmed = token.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function parseAggregatedInstances(json: unknown): GcpInstance[] {
  const items = json && typeof json === 'object' ? (json as { items?: unknown }).items : undefined;
  if (!items || typeof items !== 'object') return [];
  const instances: GcpInstance[] = [];
  for (const scoped of Object.values(items as Record<string, unknown>)) {
    if (!scoped || typeof scoped !== 'object') continue;
    const list = (scoped as { instances?: unknown }).instances;
    if (!Array.isArray(list)) continue;
    for (const raw of list) {
      const parsed = parseInstance(raw);
      if (parsed) instances.push(parsed);
    }
  }
  return instances;
}

function parseInstance(raw: unknown): GcpInstance | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const inst = raw as {
    name?: unknown;
    zone?: unknown;
    status?: unknown;
    networkInterfaces?: unknown;
  };
  if (typeof inst.name !== 'string' || inst.name.length === 0) return undefined;
  const zone = lastPathSegment(typeof inst.zone === 'string' ? inst.zone : undefined);
  if (!zone) return undefined;
  let natIp: string | undefined;
  let networkIp: string | undefined;
  if (Array.isArray(inst.networkInterfaces)) {
    for (const nic of inst.networkInterfaces) {
      if (!nic || typeof nic !== 'object') continue;
      const iface = nic as { networkIP?: unknown; accessConfigs?: unknown };
      if (!networkIp && typeof iface.networkIP === 'string') networkIp = iface.networkIP;
      if (Array.isArray(iface.accessConfigs)) {
        for (const ac of iface.accessConfigs) {
          if (ac && typeof ac === 'object' && typeof (ac as { natIP?: unknown }).natIP === 'string') {
            natIp = (ac as { natIP: string }).natIP;
          }
        }
      }
    }
  }
  return {
    name: inst.name,
    zone,
    status: typeof inst.status === 'string' ? inst.status : undefined,
    natIp,
    networkIp,
  };
}

export function parseFirewalls(json: unknown): GcpFirewall[] {
  const items = json && typeof json === 'object' ? (json as { items?: unknown }).items : undefined;
  if (!Array.isArray(items)) return [];
  const firewalls: GcpFirewall[] = [];
  for (const raw of items) {
    if (!raw || typeof raw !== 'object') continue;
    const fw = raw as { name?: unknown; direction?: unknown; sourceRanges?: unknown };
    if (typeof fw.name !== 'string' || fw.name.length === 0) continue;
    const direction = (typeof fw.direction === 'string' ? fw.direction : 'INGRESS').toUpperCase();
    const ranges = Array.isArray(fw.sourceRanges)
      ? fw.sourceRanges.filter((r): r is string => typeof r === 'string')
      : [];
    // Ingress only — egress 0.0.0.0/0 is the default and is not exposure.
    const internetOpen =
      direction === 'INGRESS' && (ranges.includes('0.0.0.0/0') || ranges.includes('::/0'));
    firewalls.push({ name: fw.name, internetOpen });
  }
  return firewalls;
}

export function parseAggregatedAddresses(json: unknown): GcpExternalIp[] {
  const items = json && typeof json === 'object' ? (json as { items?: unknown }).items : undefined;
  if (!items || typeof items !== 'object') return [];
  const addresses: GcpExternalIp[] = [];
  for (const scoped of Object.values(items as Record<string, unknown>)) {
    if (!scoped || typeof scoped !== 'object') continue;
    const list = (scoped as { addresses?: unknown }).addresses;
    if (!Array.isArray(list)) continue;
    for (const raw of list) {
      if (!raw || typeof raw !== 'object') continue;
      const addr = raw as {
        name?: unknown;
        region?: unknown;
        address?: unknown;
        addressType?: unknown;
        status?: unknown;
        users?: unknown;
      };
      if (typeof addr.name !== 'string' || typeof addr.address !== 'string') continue;
      if (addr.addressType !== 'EXTERNAL') continue;
      const region = lastPathSegment(typeof addr.region === 'string' ? addr.region : undefined);
      if (!region) continue;
      const users = Array.isArray(addr.users)
        ? addr.users.filter((u): u is string => typeof u === 'string')
        : [];
      addresses.push({
        name: addr.name,
        region,
        address: addr.address,
        status: typeof addr.status === 'string' ? addr.status : undefined,
        instance: lastPathSegment(users[0]),
      });
    }
  }
  return addresses;
}

export function parseBuckets(json: unknown): GcpBucket[] {
  const items = json && typeof json === 'object' ? (json as { items?: unknown }).items : undefined;
  if (!Array.isArray(items)) return [];
  const buckets: GcpBucket[] = [];
  for (const raw of items) {
    if (!raw || typeof raw !== 'object') continue;
    const b = raw as { name?: unknown; location?: unknown; timeCreated?: unknown };
    if (typeof b.name !== 'string' || b.name.length === 0) continue;
    buckets.push({
      name: b.name,
      location: typeof b.location === 'string' ? b.location : undefined,
      timeCreated: typeof b.timeCreated === 'string' ? b.timeCreated : undefined,
    });
  }
  return buckets;
}

/**
 * Cloud-resource inventory via GCP APIs. Same persistence path as AWS:
 * discover → UpsertAssetRequest → scheduler upsert + archiveStale scoped per
 * integrationId.
 *
 * Hosts are hardcoded to allowlisted `*.googleapis.com`. Tenant config/body/query
 * cannot set a custom endpoint. Credentials are platform-operated `env:GCP_*`
 * and fail closed when missing — there is no public-listing fallback.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — GCP list APIs do
 * not offer a reliable incremental window for this inventory.
 */
@Injectable()
export class GcpConnector implements AssetConnector {
  readonly provider = 'gcp';
  readonly assetKinds = ['cloud_resource'];
  private readonly log = rootLogger.child({ component: 'gcp-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantWritableEndpoint(ctx.config);
    const config = GcpConnectorConfig.parse(ctx.config);
    const creds = requireGcpCredentials(ctx.credentialRef);
    const accessToken = await exchangeGcpAccessToken(creds);

    const allow = new Set(config.resourceTypes?.length ? config.resourceTypes : DEFAULT_RESOURCE_TYPES);
    let seen = 0;

    if (allow.has('gce_instance')) {
      for await (const asset of this.listInstances(config.projectId, accessToken)) {
        seen += 1;
        yield asset;
      }
    }
    if (allow.has('firewall')) {
      for await (const asset of this.listFirewalls(config.projectId, accessToken)) {
        seen += 1;
        yield asset;
      }
    }
    if (allow.has('external_ip')) {
      for await (const asset of this.listExternalIps(config.projectId, accessToken)) {
        seen += 1;
        yield asset;
      }
    }
    if (allow.has('gcs_bucket')) {
      for await (const asset of this.listBuckets(config.projectId, accessToken)) {
        seen += 1;
        yield asset;
      }
    }

    this.log.info({ projectId: config.projectId, resources: seen }, 'gcp discovery complete');
  }

  private async *listInstances(
    projectId: string,
    accessToken: string,
  ): AsyncIterable<UpsertAssetRequest> {
    yield* this.pagedGet(
      gcpComputeUrl(projectId, '/aggregated/instances'),
      accessToken,
      (json) => parseAggregatedInstances(json).map((i) => instanceToAsset(projectId, i)),
      'instances',
    );
  }

  private async *listFirewalls(
    projectId: string,
    accessToken: string,
  ): AsyncIterable<UpsertAssetRequest> {
    yield* this.pagedGet(
      gcpComputeUrl(projectId, '/global/firewalls'),
      accessToken,
      (json) => parseFirewalls(json).map((f) => firewallToAsset(projectId, f)),
      'firewalls',
    );
  }

  private async *listExternalIps(
    projectId: string,
    accessToken: string,
  ): AsyncIterable<UpsertAssetRequest> {
    yield* this.pagedGet(
      gcpComputeUrl(projectId, '/aggregated/addresses'),
      accessToken,
      (json) => parseAggregatedAddresses(json).map((a) => externalIpToAsset(projectId, a)),
      'external IPs',
    );
  }

  private async *listBuckets(
    projectId: string,
    accessToken: string,
  ): AsyncIterable<UpsertAssetRequest> {
    yield* this.pagedGet(
      gcpStorageBucketsUrl(projectId),
      accessToken,
      (json) => parseBuckets(json).map((b) => bucketToAsset(projectId, b)),
      'buckets',
    );
  }

  /**
   * Complete-signal is nextPageToken, not page length. A last page of
   * GCP_PER_PAGE with no token succeeds. Only a leftover token after the cap
   * is truncated / fail-closed (so archiveStale cannot run on a partial list).
   */
  private async *pagedGet(
    baseUrl: string,
    accessToken: string,
    mapPage: (json: unknown) => UpsertAssetRequest[],
    label: string,
  ): AsyncIterable<UpsertAssetRequest> {
    let token: string | undefined;
    for (let page = 1; page <= GCP_MAX_PAGES; page++) {
      const json = await this.getJson(pagedUrl(baseUrl, token), accessToken, label);
      const assets = mapPage(json);
      for (const asset of assets) yield asset;
      token = nextPageToken(json);
      if (!token) return;
      if (page === GCP_MAX_PAGES) this.failTruncated(label);
    }
  }

  private failTruncated(label: string): never {
    this.log.error(
      { pages: GCP_MAX_PAGES, perPage: GCP_PER_PAGE, label },
      'gcp listing truncated at page cap',
    );
    throw new Error(
      `GCP listing truncated at ${GCP_MAX_PAGES * GCP_PER_PAGE} ${label} (page cap ${GCP_MAX_PAGES}); refusing to archive unseen assets`,
    );
  }

  private async getJson(url: string, accessToken: string, label: string): Promise<unknown> {
    // Belt: never send the bearer token off the allowlist even if a caller built `url`.
    allowlistedGcpUrl(url);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${accessToken}`,
      },
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new Error(`GCP ${label} API returned ${res.status}`);
    }
    return res.json();
  }
}

function pagedUrl(baseUrl: string, pageToken: string | undefined): string {
  const url = new URL(allowlistedGcpUrl(baseUrl));
  url.searchParams.set('maxResults', String(GCP_PER_PAGE));
  if (pageToken) url.searchParams.set('pageToken', pageToken);
  return allowlistedGcpUrl(url.href);
}

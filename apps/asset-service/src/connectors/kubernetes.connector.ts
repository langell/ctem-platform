import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import {
  requireAwsCredentials,
  requireAzureCredentials,
  requireGcpCredentials,
  type AwsCredentials,
} from './credentials';
import { allowlistedAwsUrl, awsServiceUrl } from './aws.egress';
import { signAwsRequest } from './aws.sigv4';
import { xmlTag } from './aws.xml';
import { allowlistedAzureArmUrl } from './azure.egress';
import { exchangeAzureAccessToken } from './azure.token';
import { exchangeGcpAccessToken } from './gcp.jwt';
import {
  AWS_REGION_RE,
  AZURE_GUID_RE,
  GCP_PROJECT_ID_RE,
  allowlistedEksApiUrl,
  allowlistedGkeApiUrl,
  aksClustersUrl,
  eksClustersUrl,
  eksDescribeClusterUrl,
  gkeClustersUrl,
  refuseTenantWritableEndpoint,
  GCP_K8S_OAUTH_SCOPE,
} from './kubernetes.egress';

/**
 * One provider `kubernetes` with `config.cloud: aws | gcp | azure`.
 * Not three sibling providers (eks/gke/aks). Credentials must match cloud
 * (`env:AWS_*` / `env:GCP_*` / `env:AZURE_*`) and fail closed.
 */
export const KubernetesCloud = z.enum(['aws', 'gcp', 'azure']);
export type KubernetesCloud = z.infer<typeof KubernetesCloud>;

export const KubernetesConnectorConfig = z
  .object({
    cloud: KubernetesCloud,
    /** AWS region id — not an API host. */
    region: z.string().regex(AWS_REGION_RE, 'must be an AWS region identifier').optional(),
    regions: z
      .array(z.string().regex(AWS_REGION_RE, 'must be an AWS region identifier'))
      .optional(),
    accountId: z
      .string()
      .regex(/^\d{12}$/)
      .optional(),
    /** GCP project id — not an API host. */
    projectId: z.string().regex(GCP_PROJECT_ID_RE, 'must be a GCP project identifier').optional(),
    /** Azure subscription GUID — not an API host. */
    subscriptionId: z
      .string()
      .regex(AZURE_GUID_RE, 'must be an Azure subscription identifier')
      .optional(),
    /** Optional cluster-name allowlist. Names only — not kube-apiserver URLs. */
    clusters: z.array(z.string().min(1)).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.cloud === 'aws' && !value.region && !(value.regions && value.regions.length > 0)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'region or regions is required when cloud is aws',
        path: ['region'],
      });
    }
    if (value.cloud === 'gcp' && !value.projectId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'projectId is required when cloud is gcp',
        path: ['projectId'],
      });
    }
    if (value.cloud === 'azure' && !value.subscriptionId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'subscriptionId is required when cloud is azure',
        path: ['subscriptionId'],
      });
    }
  });
export type KubernetesConnectorConfig = z.infer<typeof KubernetesConnectorConfig>;

export const K8S_PER_PAGE = 100;
export const K8S_MAX_PAGES = 20;

/**
 * Exact inventoried set (CTE-22 / managed-cloud lock):
 *
 *   Cluster — one `kubernetes_workload` per managed EKS / GKE / AKS cluster
 *             listed by the cloud control-plane API.
 *
 * Controllers (Deployment, StatefulSet, DaemonSet, CronJob) and Pods are
 * **not** inventoried. Those objects are served by the tenant kube-apiserver
 * (or a proxy that dials it). This slice never fetches
 * `cluster.endpoint` / kubeconfig `server` / AKS `fqdn`. Prefer controllers
 * over every Pod when a later slice can list them without that dial.
 *
 * Walk: list clusters on the allowlisted control-plane host → emit Cluster
 * assets. Namespaces and workload kinds are recorded as `_` / `Cluster`.
 */
export const KUBERNETES_WORKLOAD_KINDS = ['Cluster'] as const;
export type KubernetesWorkloadKind = (typeof KUBERNETES_WORKLOAD_KINDS)[number];

export const CLUSTER_NAMESPACE = '_';

export interface KubernetesCluster {
  cloud: KubernetesCloud;
  /** account:region | projectId | subscriptionId */
  scope: string;
  name: string;
  /** region/location or resource-group path used in the externalKey. */
  clusterIdentity: string;
  uid?: string;
  location?: string;
  version?: string;
  status?: string;
  tags: Record<string, string>;
  exposure: 'internet_facing' | 'internal' | 'unknown';
  /** Control-plane identifiers only — never a dialable kube-apiserver URL. */
  arn?: string;
  resourceId?: string;
  resourceGroup?: string;
  accountId?: string;
  projectId?: string;
  subscriptionId?: string;
  region?: string;
}

const SAFE_UID_RE = /^[A-Za-z0-9._-]+$/;

export function configuredAwsRegions(config: KubernetesConnectorConfig): string[] {
  const seen = new Set<string>();
  if (config.region) seen.add(config.region);
  for (const region of config.regions ?? []) seen.add(region);
  return [...seen];
}

export function parseCallerAccount(xml: string): string {
  const account = xmlTag(xml, 'Account');
  if (!account || !/^\d{12}$/.test(account)) {
    throw new Error('AWS STS GetCallerIdentity did not return a 12-digit account id');
  }
  return account;
}

export function jsonNextToken(json: unknown): string | undefined {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return undefined;
  const token = (json as { nextToken?: unknown }).nextToken;
  if (typeof token !== 'string') return undefined;
  const trimmed = token.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function jsonNextPageToken(json: unknown): string | undefined {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return undefined;
  const token = (json as { nextPageToken?: unknown }).nextPageToken;
  if (typeof token !== 'string') return undefined;
  const trimmed = token.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function jsonNextLink(json: unknown): string | undefined {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return undefined;
  const link = (json as { nextLink?: unknown }).nextLink;
  if (typeof link !== 'string') return undefined;
  const trimmed = link.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function jsonObjectOrThrow(json: unknown, label: string): Record<string, unknown> {
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    throw new Error(
      `Kubernetes ${label} listing was not a JSON object — refusing incomplete inventory`,
    );
  }
  return json as Record<string, unknown>;
}

function stringTags(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

export function parseEksClusterNames(json: unknown): string[] {
  const obj = jsonObjectOrThrow(json, 'EKS clusters');
  const raw = obj.clusters;
  if (raw == null) return [];
  if (!Array.isArray(raw)) {
    throw new Error('EKS cluster listing was not a JSON array — refusing incomplete inventory');
  }
  return raw.filter((n): n is string => typeof n === 'string' && n.length > 0);
}

export function parseEksCluster(json: unknown, region: string, accountId: string): KubernetesCluster {
  const obj = jsonObjectOrThrow(json, 'EKS cluster');
  const cluster = obj.cluster;
  if (!cluster || typeof cluster !== 'object' || Array.isArray(cluster)) {
    throw new Error('EKS DescribeCluster did not return a cluster — refusing incomplete inventory');
  }
  const item = cluster as {
    name?: unknown;
    arn?: unknown;
    version?: unknown;
    status?: unknown;
    tags?: unknown;
    resourcesVpcConfig?: unknown;
  };
  if (typeof item.name !== 'string' || item.name.length === 0) {
    throw new Error('EKS DescribeCluster omitted cluster name — refusing incomplete inventory');
  }
  const vpc =
    item.resourcesVpcConfig && typeof item.resourcesVpcConfig === 'object'
      ? (item.resourcesVpcConfig as { endpointPublicAccess?: unknown })
      : {};
  // `endpoint` is present on the payload and is the kube-apiserver. Never read
  // it into a URL. Public-access is a boolean on the control-plane object.
  const publicAccess = vpc.endpointPublicAccess === true;
  return {
    cloud: 'aws',
    scope: `${accountId}:${region}`,
    name: item.name,
    clusterIdentity: item.name,
    location: region,
    region,
    accountId,
    arn: typeof item.arn === 'string' ? item.arn : undefined,
    version: typeof item.version === 'string' ? item.version : undefined,
    status: typeof item.status === 'string' ? item.status : undefined,
    tags: stringTags(item.tags),
    exposure: publicAccess ? 'internet_facing' : 'internal',
  };
}

export function parseGkeClusters(json: unknown, projectId: string): KubernetesCluster[] {
  const obj = jsonObjectOrThrow(json, 'GKE clusters');
  const raw = obj.clusters;
  if (raw == null) return [];
  if (!Array.isArray(raw)) {
    throw new Error('GKE cluster listing was not a JSON array — refusing incomplete inventory');
  }
  const out: KubernetesCluster[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const c = item as {
      name?: unknown;
      location?: unknown;
      id?: unknown;
      status?: unknown;
      currentMasterVersion?: unknown;
      resourceLabels?: unknown;
      privateClusterConfig?: unknown;
    };
    if (typeof c.name !== 'string' || c.name.length === 0) continue;
    const location = typeof c.location === 'string' ? c.location : 'unknown';
    const privateCfg =
      c.privateClusterConfig && typeof c.privateClusterConfig === 'object'
        ? (c.privateClusterConfig as { enablePrivateEndpoint?: unknown })
        : {};
    // `endpoint` is the kube-apiserver address. Never dial it.
    const privateEndpoint = privateCfg.enablePrivateEndpoint === true;
    out.push({
      cloud: 'gcp',
      scope: projectId,
      name: c.name,
      clusterIdentity: `${location}/${c.name}`,
      uid: typeof c.id === 'string' || typeof c.id === 'number' ? String(c.id) : undefined,
      location,
      projectId,
      version: typeof c.currentMasterVersion === 'string' ? c.currentMasterVersion : undefined,
      status: typeof c.status === 'string' ? c.status : undefined,
      tags: stringTags(c.resourceLabels),
      exposure: privateEndpoint ? 'internal' : 'internet_facing',
    });
  }
  return out;
}

export function resourceGroupFromId(id: string | undefined): string | undefined {
  if (!id) return undefined;
  const match = id.match(/\/resourceGroups\/([^/]+)\//i);
  return match?.[1];
}

export function parseAksClusters(json: unknown, subscriptionId: string): KubernetesCluster[] {
  const obj = jsonObjectOrThrow(json, 'AKS clusters');
  const raw = obj.value;
  if (raw == null) return [];
  if (!Array.isArray(raw)) {
    throw new Error('AKS cluster listing was not a JSON array — refusing incomplete inventory');
  }
  const out: KubernetesCluster[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const c = item as {
      name?: unknown;
      id?: unknown;
      location?: unknown;
      tags?: unknown;
      properties?: unknown;
    };
    if (typeof c.name !== 'string' || c.name.length === 0) continue;
    if (typeof c.id !== 'string') continue;
    const resourceGroup = resourceGroupFromId(c.id);
    if (!resourceGroup) continue;
    const props =
      c.properties && typeof c.properties === 'object'
        ? (c.properties as {
            kubernetesVersion?: unknown;
            provisioningState?: unknown;
            apiServerAccessProfile?: unknown;
          })
        : {};
    const access =
      props.apiServerAccessProfile && typeof props.apiServerAccessProfile === 'object'
        ? (props.apiServerAccessProfile as { enablePrivateCluster?: unknown })
        : {};
    // `fqdn` / `privateFQDN` are kube-apiserver hosts. Never dial them.
    const privateCluster = access.enablePrivateCluster === true;
    out.push({
      cloud: 'azure',
      scope: subscriptionId,
      name: c.name,
      clusterIdentity: `${resourceGroup}/${c.name}`,
      location: typeof c.location === 'string' ? c.location : undefined,
      subscriptionId,
      resourceId: c.id,
      resourceGroup,
      version: typeof props.kubernetesVersion === 'string' ? props.kubernetesVersion : undefined,
      status: typeof props.provisioningState === 'string' ? props.provisioningState : undefined,
      tags: stringTags(c.tags),
      exposure: privateCluster ? 'internal' : 'internet_facing',
    });
  }
  return out;
}

export function kubernetesExternalKey(cluster: KubernetesCluster): string {
  const ns = CLUSTER_NAMESPACE;
  const kind = 'Cluster';
  const base = `k8s:${cluster.cloud}:${cluster.scope}:${cluster.clusterIdentity}:${ns}:${kind}:${cluster.name}`;
  if (cluster.uid && SAFE_UID_RE.test(cluster.uid)) return `${base}:${cluster.uid}`;
  return base;
}

export function clusterToAsset(cluster: KubernetesCluster): UpsertAssetRequest {
  return {
    kind: 'kubernetes_workload',
    externalKey: kubernetesExternalKey(cluster),
    name: cluster.name,
    source: 'kubernetes',
    exposure: cluster.exposure,
    attributes: {
      cloud: cluster.cloud,
      workloadKind: 'Cluster',
      namespace: CLUSTER_NAMESPACE,
      cluster: cluster.name,
      clusterIdentity: cluster.clusterIdentity,
      location: cluster.location ?? null,
      version: cluster.version ?? null,
      status: cluster.status ?? null,
      uid: cluster.uid ?? cluster.arn ?? cluster.resourceId ?? null,
      tags: cluster.tags,
      accountId: cluster.accountId ?? null,
      projectId: cluster.projectId ?? null,
      subscriptionId: cluster.subscriptionId ?? null,
      region: cluster.region ?? null,
      resourceGroup: cluster.resourceGroup ?? null,
      arn: cluster.arn ?? null,
      resourceId: cluster.resourceId ?? null,
    },
  };
}

/**
 * Managed Kubernetes inventory via EKS / GKE / AKS control-plane APIs.
 * Same persistence path as AWS/GCP/Azure/ECR: discover → UpsertAssetRequest
 * → scheduler upsert + archiveStale scoped per integrationId.
 *
 * Hosts are hardcoded to the matching cloud allowlist plus the EKS/GKE/AKS
 * management hosts on those suffixes. Tenant config cannot set a
 * kube-apiserver. Credentials match `config.cloud` and fail closed.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — list APIs do not
 * offer a reliable incremental window for this inventory.
 */
@Injectable()
export class KubernetesConnector implements AssetConnector {
  readonly provider = 'kubernetes';
  readonly assetKinds = ['kubernetes_workload'];
  private readonly log = rootLogger.child({ component: 'kubernetes-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantWritableEndpoint(ctx.config);
    const config = KubernetesConnectorConfig.parse(ctx.config);
    const allow = config.clusters?.length ? new Set(config.clusters) : null;
    let seen = 0;
    const yielded = new Set<string>();

    const emit = function* (cluster: KubernetesCluster): Generator<UpsertAssetRequest> {
      if (allow && !allow.has(cluster.name)) return;
      const asset = clusterToAsset(cluster);
      if (yielded.has(asset.externalKey)) return;
      yielded.add(asset.externalKey);
      seen += 1;
      yield asset;
    };

    if (config.cloud === 'aws') {
      for await (const cluster of this.discoverAws(ctx, config)) {
        yield* emit(cluster);
      }
    } else if (config.cloud === 'gcp') {
      for await (const cluster of this.discoverGcp(ctx, config)) {
        yield* emit(cluster);
      }
    } else {
      for await (const cluster of this.discoverAzure(ctx, config)) {
        yield* emit(cluster);
      }
    }

    this.log.info({ cloud: config.cloud, clusters: seen }, 'kubernetes discovery complete');
  }

  private async *discoverAws(
    ctx: DiscoveryContext,
    config: KubernetesConnectorConfig,
  ): AsyncIterable<KubernetesCluster> {
    const creds = requireAwsCredentials(ctx.credentialRef);
    const regions = configuredAwsRegions(config);
    const stsRegion = config.region ?? regions[0]!;
    const accountId = await this.callerAccount(stsRegion, creds);
    if (config.accountId && config.accountId !== accountId) {
      throw new Error(
        `AWS account ${accountId} does not match configured accountId ${config.accountId} — refusing to inventory`,
      );
    }
    for (const region of regions) {
      for await (const name of this.listEksNames(region, creds)) {
        const json = await this.eksGet(eksDescribeClusterUrl(region, name), region, creds, `cluster ${name}`);
        yield parseEksCluster(json, region, accountId);
      }
    }
  }

  private async *discoverGcp(
    ctx: DiscoveryContext,
    config: KubernetesConnectorConfig,
  ): AsyncIterable<KubernetesCluster> {
    const creds = requireGcpCredentials(ctx.credentialRef);
    const accessToken = await exchangeGcpAccessToken(creds, GCP_K8S_OAUTH_SCOPE);
    const projectId = config.projectId!;
    yield* this.pagedGke(projectId, accessToken);
  }

  private async *discoverAzure(
    ctx: DiscoveryContext,
    config: KubernetesConnectorConfig,
  ): AsyncIterable<KubernetesCluster> {
    const creds = requireAzureCredentials(ctx.credentialRef);
    const accessToken = await exchangeAzureAccessToken(creds);
    const subscriptionId = config.subscriptionId!.toLowerCase();
    yield* this.pagedAks(subscriptionId, accessToken);
  }

  private async callerAccount(region: string, creds: AwsCredentials): Promise<string> {
    const url = awsServiceUrl('sts', region);
    const body = new URLSearchParams({
      Action: 'GetCallerIdentity',
      Version: '2011-06-15',
    }).toString();
    const signed = signAwsRequest({
      method: 'POST',
      url,
      region,
      service: 'sts',
      credentials: creds,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    const xml = await this.sendAws(signed, 'sts', 'GetCallerIdentity');
    return parseCallerAccount(xml);
  }

  /**
   * Complete-signal is missing nextToken, not page length. A last page of
   * K8S_PER_PAGE with no token succeeds. Only a leftover nextToken after the
   * cap is truncated / fail-closed (so archiveStale cannot run on a partial
   * list).
   */
  private async *listEksNames(region: string, creds: AwsCredentials): AsyncIterable<string> {
    let token: string | undefined;
    for (let page = 1; page <= K8S_MAX_PAGES; page++) {
      const json = await this.eksGet(eksClustersUrl(region, token), region, creds, 'clusters');
      for (const name of parseEksClusterNames(json)) yield name;
      token = jsonNextToken(json);
      if (!token) return;
      if (page === K8S_MAX_PAGES) this.failTruncated('EKS clusters');
    }
  }

  private async *pagedGke(projectId: string, accessToken: string): AsyncIterable<KubernetesCluster> {
    let token: string | undefined;
    for (let page = 1; page <= K8S_MAX_PAGES; page++) {
      const json = await this.gkeGet(gkeClustersUrl(projectId, token), accessToken, 'clusters');
      for (const cluster of parseGkeClusters(json, projectId)) yield cluster;
      token = jsonNextPageToken(json);
      if (!token) return;
      if (page === K8S_MAX_PAGES) this.failTruncated('GKE clusters');
    }
  }

  private async *pagedAks(
    subscriptionId: string,
    accessToken: string,
  ): AsyncIterable<KubernetesCluster> {
    let url: string | undefined = aksClustersUrl(subscriptionId);
    for (let page = 1; page <= K8S_MAX_PAGES; page++) {
      const json = await this.aksGet(url, accessToken, 'clusters');
      for (const cluster of parseAksClusters(json, subscriptionId)) yield cluster;
      const link = jsonNextLink(json);
      if (!link) return;
      url = allowlistedAzureArmUrl(link);
      if (page === K8S_MAX_PAGES) this.failTruncated('AKS clusters');
    }
  }

  private failTruncated(label: string): never {
    this.log.error(
      { pages: K8S_MAX_PAGES, perPage: K8S_PER_PAGE, label },
      'kubernetes listing truncated at page cap',
    );
    throw new Error(
      `Kubernetes listing truncated at ${K8S_MAX_PAGES * K8S_PER_PAGE} ${label} (page cap ${K8S_MAX_PAGES}); refusing to archive unseen assets`,
    );
  }

  private async eksGet(
    url: string,
    region: string,
    creds: AwsCredentials,
    label: string,
  ): Promise<unknown> {
    const signed = signAwsRequest({
      method: 'GET',
      url: allowlistedEksApiUrl(url),
      region,
      service: 'eks',
      credentials: creds,
      headers: { accept: 'application/json' },
    });
    const text = await this.sendAws(signed, 'eks', label);
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new Error(`EKS ${label} listing was not JSON — refusing incomplete inventory`);
    }
  }

  private async gkeGet(url: string, accessToken: string, label: string): Promise<unknown> {
    allowlistedGkeApiUrl(url);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${accessToken}`,
      },
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new Error(`GKE ${label} API returned ${res.status}`);
    }
    return res.json();
  }

  private async aksGet(url: string, accessToken: string, label: string): Promise<unknown> {
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
      throw new Error(`AKS ${label} API returned ${res.status}`);
    }
    return res.json();
  }

  private async sendAws(
    signed: { url: string; method: 'GET' | 'POST'; headers: Record<string, string>; body?: string },
    service: 'eks' | 'sts',
    action: string,
  ): Promise<string> {
    if (service === 'eks') allowlistedEksApiUrl(signed.url);
    else allowlistedAwsUrl(signed.url);
    const res = await fetch(signed.url, {
      method: signed.method,
      headers: signed.headers,
      body: signed.method === 'POST' ? signed.body : undefined,
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new Error(`EKS ${service} API returned ${res.status} for ${action}`);
    }
    return res.text();
  }
}

/**
 * Kubernetes discovery egress (managed cloud only). CTEM talks to the cloud
 * control-plane APIs — `api.eks.{region}.amazonaws.com`,
 * `container.googleapis.com`, and Azure ARM — never a tenant kube-apiserver.
 *
 * Forbidden destinations include free-form `apiServerUrl`, kubeconfig
 * `clusters[].cluster.server`, `https://10.x:6443`,
 * `{id}.gr7.{region}.eks.amazonaws.com`, GKE `endpoint`, and AKS `fqdn` /
 * `privateFQDN`. Those values may appear in Describe/list payloads; they are
 * attributes at most and must never become a fetch URL.
 *
 * Tenant config cannot set endpoint / apiServerUrl / server / baseUrl / host
 * / kubeconfig (including a path-as-URL). EXTRA_*_HOST_KEYS is refused.
 */

import {
  AWS_API_SUFFIX,
  AWS_REGION_RE,
  allowlistedAwsUrl,
  awsServiceUrl,
} from './aws.egress';
import {
  AZURE_ARM_HOST,
  AZURE_GUID_RE,
  allowlistedAzureArmUrl,
  azureArmListUrl,
} from './azure.egress';
import {
  GCP_API_SUFFIX,
  GCP_PROJECT_ID_RE,
  allowlistedGcpUrl,
  assertGcpProjectId,
} from './gcp.egress';

export const GKE_API_HOST = 'container.googleapis.com';
export const AKS_CONTAINERSERVICE_API_VERSION = '2024-09-01';

/** Inventory-only GKE scope. Not cloud-platform, not write, not kube-apiserver. */
export const GCP_K8S_OAUTH_SCOPE = 'https://www.googleapis.com/auth/container.readonly';

export class KubernetesEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KubernetesEgressError';
  }
}

/**
 * Keys a tenant might use to point discovery at a kube-apiserver or any
 * non-control-plane host. `cloud` is an identifier (aws|gcp|azure), not a host.
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
  'apiServerUrl',
  'server',
  'kubeconfig',
  'kubeConfig',
  'kube_config',
  'kubeconfigPath',
  'kubeconfigUrl',
  'kubeConfigPath',
  'kubeConfigUrl',
  'clusterEndpoint',
  'clusterServer',
  'kubernetesUrl',
  'kubernetesHost',
  'tokenUrl',
  'tokenUri',
  'token_uri',
  'armEndpoint',
  'resourceManagerUrl',
  'authority',
  'loginUrl',
  'environment',
  'universeDomain',
  'universe_domain',
] as const;

/** GitLab-style extra-host allowlist. Kubernetes refuses this pattern entirely. */
export const EXTRA_HOST_KEY_RE = /^EXTRA_.+_HOST(_KEYS)?$/i;

export function isEksApiHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const match = host.match(/^api\.eks\.([a-z0-9-]+)\.amazonaws\.com$/);
  if (!match) return false;
  return AWS_REGION_RE.test(match[1]!);
}

export function isGkeApiHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === GKE_API_HOST;
}

export function allowlistedEksApiUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new KubernetesEgressError('Refusing unparseable EKS API URL');
  }
  const canonical = allowlistedAwsUrl(raw);
  if (!isEksApiHost(parsed.hostname)) {
    throw new KubernetesEgressError(
      `Refusing EKS API host '${parsed.hostname}' — only api.eks.{region}.${AWS_API_SUFFIX} is allowlisted`,
    );
  }
  return canonical;
}

export function allowlistedGkeApiUrl(raw: string): string {
  const canonical = allowlistedGcpUrl(raw);
  const parsed = new URL(canonical);
  if (!isGkeApiHost(parsed.hostname)) {
    throw new KubernetesEgressError(
      `Refusing GKE API host '${parsed.hostname}' — only ${GKE_API_HOST} is allowlisted`,
    );
  }
  return canonical;
}

export function eksApiUrl(region: string): string {
  if (!AWS_REGION_RE.test(region)) {
    throw new KubernetesEgressError(
      `Refusing AWS region '${region}' — not a valid AWS region identifier`,
    );
  }
  return allowlistedEksApiUrl(awsServiceUrl('eks', region));
}

export function eksClustersUrl(region: string, nextToken?: string): string {
  const base = new URL(eksApiUrl(region));
  base.pathname = '/clusters';
  base.searchParams.set('maxResults', '100');
  if (nextToken) base.searchParams.set('nextToken', nextToken);
  return allowlistedEksApiUrl(base.href);
}

export function eksDescribeClusterUrl(region: string, name: string): string {
  if (!name || /[/?#]/.test(name) || /^https?:\/\//i.test(name)) {
    throw new KubernetesEgressError('Refusing EKS cluster name that is not an identifier');
  }
  const base = new URL(eksApiUrl(region));
  base.pathname = `/clusters/${encodeURIComponent(name)}`;
  return allowlistedEksApiUrl(base.href);
}

export function gkeClustersUrl(projectId: string, pageToken?: string): string {
  assertGcpProjectId(projectId);
  const url = new URL(
    `https://${GKE_API_HOST}/v1/projects/${encodeURIComponent(projectId)}/locations/-/clusters`,
  );
  url.searchParams.set('pageSize', '100');
  if (pageToken) url.searchParams.set('pageToken', pageToken);
  return allowlistedGkeApiUrl(url.href);
}

export function aksClustersUrl(subscriptionId: string): string {
  if (/^https?:\/\//i.test(subscriptionId) || !AZURE_GUID_RE.test(subscriptionId)) {
    throw new KubernetesEgressError(
      `Refusing Azure subscriptionId '${subscriptionId}' — not a valid Azure subscription identifier`,
    );
  }
  return allowlistedAzureArmUrl(
    azureArmListUrl(
      subscriptionId,
      '/providers/Microsoft.ContainerService/managedClusters',
      AKS_CONTAINERSERVICE_API_VERSION,
    ),
  );
}

function valueIsSet(value: unknown): boolean {
  return value != null && value !== '';
}

function refuseIfUrl(value: unknown, field: string): void {
  if (typeof value === 'string' && /^https?:\/\//i.test(value.trim())) {
    throw new KubernetesEgressError(
      `Refusing tenant-writable Kubernetes endpoint (${field}) — API hosts are the cloud control plane, not tenant-configurable`,
    );
  }
}

/**
 * Tenant-writable integration config must never choose a kube-apiserver or
 * extra host. `cloud` / region / projectId / subscriptionId are identifiers.
 */
export function refuseTenantWritableEndpoint(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (EXTRA_HOST_KEY_RE.test(key) && valueIsSet(config[key])) {
      throw new KubernetesEgressError(
        `Refusing tenant-writable Kubernetes endpoint (${key}) — EXTRA_*_HOST_KEYS is not permitted`,
      );
    }
  }
  for (const key of TENANT_ENDPOINT_KEYS) {
    if (valueIsSet(config[key])) {
      throw new KubernetesEgressError(
        `Refusing tenant-writable Kubernetes endpoint (${key}) — API hosts are the cloud control plane, not tenant-configurable`,
      );
    }
  }
  refuseIfUrl(config.cloud, 'cloud');
  refuseIfUrl(config.region, 'region');
  refuseIfUrl(config.projectId, 'projectId');
  refuseIfUrl(config.subscriptionId, 'subscriptionId');
  const regions = config.regions;
  if (Array.isArray(regions)) {
    for (const item of regions) refuseIfUrl(item, 'regions');
  }
  const clusters = config.clusters;
  if (Array.isArray(clusters)) {
    for (const item of clusters) refuseIfUrl(item, 'clusters');
  }
}

export { AWS_API_SUFFIX, AWS_REGION_RE, AZURE_ARM_HOST, AZURE_GUID_RE, GCP_API_SUFFIX, GCP_PROJECT_ID_RE };

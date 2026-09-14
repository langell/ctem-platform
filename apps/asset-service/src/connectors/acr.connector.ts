import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { requireAzureCredentials, type AzureCredentials } from './credentials';
import { ACR_AAD_SCOPE, AZURE_GUID_RE, allowlistedAzureArmUrl } from './azure.egress';
import { exchangeAzureAccessToken } from './azure.token';
import {
  ACR_REGISTRY_NAME_RE,
  ACR_REPOSITORY_RE,
  AZURE_RESOURCE_GROUP_RE,
  acrArmRegistriesUrl,
  acrCatalogUrl,
  acrManifestsUrl,
  acrOauthExchangeUrl,
  acrOauthTokenUrl,
  allowlistedAcrDataUrl,
  allowlistedAcrNextUrl,
  assertAcrLoginServer,
  nextRelFromLinkHeader,
  pinAcrLoginServer,
  refuseTenantWritableEndpoint,
} from './acr.egress';

export const AcrConnectorConfig = z
  .object({
    /** Subscription to inventory. This is an Azure subscription GUID, not an API host. */
    subscriptionId: z.string().regex(AZURE_GUID_RE, 'must be an Azure subscription identifier'),
    /** Optional resource group id filter; omit to list the whole subscription. */
    resourceGroup: z
      .string()
      .regex(AZURE_RESOURCE_GROUP_RE, 'must be an Azure resource group identifier')
      .optional(),
    /** Additional resource groups; unioned with `resourceGroup`. */
    resourceGroups: z
      .array(
        z.string().regex(AZURE_RESOURCE_GROUP_RE, 'must be an Azure resource group identifier'),
      )
      .optional(),
    /** Optional registry name filter; omit to inventory every registry in scope. */
    registry: z
      .string()
      .regex(ACR_REGISTRY_NAME_RE, 'must be an Azure Container Registry name')
      .optional(),
    /** Alias of `registry` — still an identifier, never a loginServer host. */
    registryName: z
      .string()
      .regex(ACR_REGISTRY_NAME_RE, 'must be an Azure Container Registry name')
      .optional(),
    /** Additional registry names; unioned with `registry` / `registryName`. */
    registries: z
      .array(z.string().regex(ACR_REGISTRY_NAME_RE, 'must be an Azure Container Registry name'))
      .optional(),
    /** Optional allowlist of repository names; omit to inventory everything. */
    repositories: z
      .array(z.string().regex(ACR_REPOSITORY_RE, 'must be an ACR repository identifier'))
      .optional(),
  })
  .superRefine((value, ctx) => {
    if (
      value.registry &&
      value.registryName &&
      value.registry.toLowerCase() !== value.registryName.toLowerCase()
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'registry and registryName must match',
        path: ['registryName'],
      });
    }
  });
export type AcrConnectorConfig = z.infer<typeof AcrConnectorConfig>;

export const ACR_PER_PAGE = 100;
export const ACR_MAX_PAGES = 20;

/** OCI identity is the content digest, never a mutable tag. */
export const SHA256_DIGEST_RE = /^sha256:[a-f0-9]{64}$/i;

export interface AcrRegistry {
  name: string;
  resourceGroup: string;
  loginServer: string;
  location?: string;
  id?: string;
}

export interface AcrImage {
  subscriptionId: string;
  resourceGroup: string;
  registry: string;
  loginServer: string;
  repository: string;
  digest: string;
  tags: string[];
  architecture?: string;
  os?: string;
  mediaType?: string;
  createdTime?: string;
  lastUpdateTime?: string;
  imageSize?: number;
}

export function configuredResourceGroups(config: AcrConnectorConfig): string[] {
  const seen = new Set<string>();
  if (config.resourceGroup) seen.add(config.resourceGroup);
  for (const rg of config.resourceGroups ?? []) seen.add(rg);
  return [...seen];
}

export function configuredRegistries(config: AcrConnectorConfig): string[] {
  const seen = new Set<string>();
  if (config.registry) seen.add(config.registry.toLowerCase());
  if (config.registryName) seen.add(config.registryName.toLowerCase());
  for (const name of config.registries ?? []) seen.add(name.toLowerCase());
  return [...seen];
}

export function imageDigest(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || !SHA256_DIGEST_RE.test(raw)) return undefined;
  return raw.toLowerCase();
}

export function imageTags(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((t): t is string => typeof t === 'string' && t.length > 0);
}

export function resourceGroupFromId(id: string | undefined): string | undefined {
  if (!id) return undefined;
  const match = id.match(/\/resourceGroups\/([^/]+)\//i);
  return match?.[1];
}

/** Complete-signal is a missing nextLink, not page length. */
export function nextLink(json: unknown): string | undefined {
  if (!json || typeof json !== 'object') return undefined;
  const link = (json as { nextLink?: unknown }).nextLink;
  if (typeof link !== 'string') return undefined;
  const trimmed = link.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function parseRegistries(json: unknown): AcrRegistry[] {
  const obj = jsonObjectOrThrow(json, 'registries');
  const items = jsonArrayField(obj, 'value', 'registries');
  const registries: AcrRegistry[] = [];
  for (const raw of items) {
    const parsed = parseRegistryResource(raw);
    if (parsed) registries.push(parsed);
  }
  return registries;
}

/** A GET-by-name ARM body is a single resource, not `{ value: [...] }`. */
export function parseRegistryResource(raw: unknown): AcrRegistry | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const item = raw as {
    name?: unknown;
    id?: unknown;
    location?: unknown;
    properties?: unknown;
  };
  if (typeof item.name !== 'string' || !ACR_REGISTRY_NAME_RE.test(item.name)) return undefined;
  if (typeof item.id !== 'string') return undefined;
  const resourceGroup = resourceGroupFromId(item.id);
  if (!resourceGroup) return undefined;
  const props =
    item.properties && typeof item.properties === 'object'
      ? (item.properties as { loginServer?: unknown })
      : {};
  if (typeof props.loginServer !== 'string') return undefined;
  const loginServer = assertAcrLoginServer(item.name, props.loginServer);
  return {
    name: item.name.toLowerCase(),
    resourceGroup,
    loginServer,
    location: typeof item.location === 'string' ? item.location : undefined,
    id: item.id,
  };
}

export function parseRepositories(json: unknown): string[] {
  const obj = jsonObjectOrThrow(json, 'catalog');
  const names: string[] = [];
  for (const raw of jsonArrayField(obj, 'repositories', 'catalog')) {
    if (typeof raw !== 'string' || !ACR_REPOSITORY_RE.test(raw)) continue;
    names.push(raw);
  }
  return names;
}

export function parseManifests(json: unknown): Array<{
  digest: string;
  tags: string[];
  architecture?: string;
  os?: string;
  mediaType?: string;
  createdTime?: string;
  lastUpdateTime?: string;
  imageSize?: number;
}> {
  const obj = jsonObjectOrThrow(json, 'manifests');
  const manifests: Array<{
    digest: string;
    tags: string[];
    architecture?: string;
    os?: string;
    mediaType?: string;
    createdTime?: string;
    lastUpdateTime?: string;
    imageSize?: number;
  }> = [];
  for (const raw of jsonArrayField(obj, 'manifests', 'manifests')) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as {
      digest?: unknown;
      tags?: unknown;
      architecture?: unknown;
      os?: unknown;
      mediaType?: unknown;
      createdTime?: unknown;
      lastUpdateTime?: unknown;
      imageSize?: unknown;
    };
    const digest = imageDigest(item.digest);
    if (!digest) continue;
    const parsed: {
      digest: string;
      tags: string[];
      architecture?: string;
      os?: string;
      mediaType?: string;
      createdTime?: string;
      lastUpdateTime?: string;
      imageSize?: number;
    } = { digest, tags: imageTags(item.tags) };
    if (typeof item.architecture === 'string') parsed.architecture = item.architecture;
    if (typeof item.os === 'string') parsed.os = item.os;
    if (typeof item.mediaType === 'string') parsed.mediaType = item.mediaType;
    if (typeof item.createdTime === 'string') parsed.createdTime = item.createdTime;
    if (typeof item.lastUpdateTime === 'string') parsed.lastUpdateTime = item.lastUpdateTime;
    if (typeof item.imageSize === 'number') parsed.imageSize = item.imageSize;
    manifests.push(parsed);
  }
  return manifests;
}

/**
 * Digest identity. Form:
 *   `acr:{subscriptionId}/{resourceGroup}/{registry}/{repository}@{digest}`
 *
 * subscriptionId, resourceGroup, and registry are Azure identifiers (not
 * hosts / loginServers). `{repository}` may contain `/`. Digest is required;
 * tags live in attributes so a retag does not fork assets.
 */
export function imageToAsset(image: AcrImage): UpsertAssetRequest {
  return {
    kind: 'container_image',
    externalKey: `acr:${image.subscriptionId}/${image.resourceGroup}/${image.registry}/${image.repository}@${image.digest}`,
    name: `${image.registry}/${image.repository}`,
    source: 'acr',
    exposure: 'internal',
    attributes: {
      subscriptionId: image.subscriptionId,
      resourceGroup: image.resourceGroup,
      registry: image.registry,
      loginServer: image.loginServer,
      repository: image.repository,
      digest: image.digest,
      tags: image.tags,
      architecture: image.architecture ?? null,
      os: image.os ?? null,
      mediaType: image.mediaType ?? null,
      createdTime: image.createdTime ?? null,
      lastUpdateTime: image.lastUpdateTime ?? null,
      imageSize: image.imageSize ?? null,
    },
  };
}

function jsonObjectOrThrow(json: unknown, label: string): Record<string, unknown> {
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    throw new Error(`ACR ${label} listing was not a JSON object — refusing incomplete inventory`);
  }
  return json as Record<string, unknown>;
}

function jsonArrayField(obj: Record<string, unknown>, field: string, label: string): unknown[] {
  const value = obj[field];
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`ACR ${label} listing was not a JSON array — refusing incomplete inventory`);
  }
  return value;
}

/**
 * Container-image inventory via Azure Container Registry (ARM list + ACR
 * `/acr/v1/_catalog` and `/acr/v1/{repository}/_manifests`). Same persistence
 * path as ECR/GCR: discover → UpsertAssetRequest → scheduler upsert +
 * archiveStale scoped per integrationId.
 *
 * Hosts are hardcoded to allowlisted `login.microsoftonline.com` (token),
 * `management.azure.com` (ARM), and the ARM-returned `{loginServer}` on
 * `*.azurecr.io` (catalog / manifest list). Tenant config cannot set a
 * registry/API host. Credentials are platform-operated `env:AZURE_*` and fail
 * closed when missing — there is no public-listing fallback.
 *
 * Identity is the image digest. Tags live in attributes so a retag does not
 * fork assets. This connector does not pull layers or fetch OCI blobs —
 * inventory is ARM + ACR metadata list APIs only.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — ACR list APIs do
 * not offer a reliable incremental window for this inventory.
 */
@Injectable()
export class AcrConnector implements AssetConnector {
  readonly provider = 'acr';
  readonly assetKinds = ['container_image'];
  private readonly log = rootLogger.child({ component: 'acr-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantWritableEndpoint(ctx.config);
    const config = AcrConnectorConfig.parse(ctx.config);
    const creds = requireAzureCredentials(ctx.credentialRef);
    const armToken = await exchangeAzureAccessToken(creds);
    const acrAadToken = await exchangeAzureAccessToken(creds, ACR_AAD_SCOPE);

    const subscriptionId = config.subscriptionId.toLowerCase();
    const resourceGroups = configuredResourceGroups(config);
    const registryAllow = configuredRegistries(config);
    const repoAllow = config.repositories?.length ? new Set(config.repositories) : null;

    let seen = 0;
    const yielded = new Set<string>();

    for await (const registry of this.listRegistries(subscriptionId, resourceGroups, armToken)) {
      if (registryAllow.length > 0 && !registryAllow.includes(registry.name)) continue;

      const refreshToken = await this.exchangeAcrRefreshToken(
        registry.loginServer,
        acrAadToken,
        creds,
      );
      const catalogToken = await this.acrAccessToken(
        registry.loginServer,
        refreshToken,
        'registry:catalog:*',
      );

      for await (const repository of this.listRepositories(registry.loginServer, catalogToken)) {
        if (repoAllow && !repoAllow.has(repository)) continue;
        const metadataToken = await this.acrAccessToken(
          registry.loginServer,
          refreshToken,
          `repository:${repository}:metadata_read`,
        );
        for await (const manifest of this.listManifests(
          registry.loginServer,
          repository,
          metadataToken,
        )) {
          const asset = imageToAsset({
            subscriptionId,
            resourceGroup: registry.resourceGroup,
            registry: registry.name,
            loginServer: registry.loginServer,
            repository,
            digest: manifest.digest,
            tags: manifest.tags,
            architecture: manifest.architecture,
            os: manifest.os,
            mediaType: manifest.mediaType,
            createdTime: manifest.createdTime,
            lastUpdateTime: manifest.lastUpdateTime,
            imageSize: manifest.imageSize,
          });
          if (yielded.has(asset.externalKey)) continue;
          yielded.add(asset.externalKey);
          seen += 1;
          yield asset;
        }
      }
    }

    this.log.info({ subscriptionId, images: seen }, 'acr discovery complete');
  }

  private async *listRegistries(
    subscriptionId: string,
    resourceGroups: string[],
    armToken: string,
  ): AsyncIterable<AcrRegistry> {
    const scopes = resourceGroups.length > 0 ? resourceGroups : [undefined];
    for (const resourceGroup of scopes) {
      yield* this.pagedArm(
        acrArmRegistriesUrl(subscriptionId, resourceGroup),
        armToken,
        (json) => parseRegistries(json),
        resourceGroup ? `registries in ${resourceGroup}` : 'registries',
      );
    }
  }

  private async *listRepositories(loginServer: string, accessToken: string): AsyncIterable<string> {
    yield* this.pagedAcr(
      acrCatalogUrl(loginServer),
      loginServer,
      accessToken,
      (json) => parseRepositories(json),
      'catalog',
    );
  }

  private async *listManifests(
    loginServer: string,
    repository: string,
    accessToken: string,
  ): AsyncIterable<ReturnType<typeof parseManifests>[number]> {
    yield* this.pagedAcr(
      acrManifestsUrl(loginServer, repository),
      loginServer,
      accessToken,
      (json) => parseManifests(json),
      `manifests for ${repository}`,
    );
  }

  /**
   * Complete-signal is nextLink, not page length. A last page of
   * ACR_PER_PAGE with no nextLink succeeds. Only a leftover nextLink after
   * the cap is truncated / fail-closed (so archiveStale cannot run on a
   * partial list). nextLink is a full URL — parse and allowlist before GET.
   */
  private async *pagedArm<T>(
    firstUrl: string,
    accessToken: string,
    mapPage: (json: unknown) => T[],
    label: string,
  ): AsyncIterable<T> {
    let url: string | undefined = allowlistedAzureArmUrl(firstUrl);
    for (let page = 1; page <= ACR_MAX_PAGES; page++) {
      const json = await this.getArmJson(url, accessToken, label);
      for (const item of mapPage(json)) yield item;
      const link = nextLink(json);
      if (!link) return;
      url = allowlistedAzureArmUrl(link);
      if (page === ACR_MAX_PAGES) this.failTruncated(label);
    }
  }

  /**
   * Complete-signal is missing Link rel=next, not page length. A last page of
   * ACR_PER_PAGE with no next succeeds. next is allowlisted to the same
   * ARM-derived loginServer before GET.
   */
  private async *pagedAcr<T>(
    firstUrl: string,
    loginServer: string,
    accessToken: string,
    mapPage: (json: unknown) => T[],
    label: string,
  ): AsyncIterable<T> {
    const host = pinAcrLoginServer(loginServer);
    let url = allowlistedAcrDataUrl(firstUrl, host);
    for (let page = 1; page <= ACR_MAX_PAGES; page++) {
      const { json, next } = await this.getAcrJson(url, host, accessToken, label);
      for (const item of mapPage(json)) yield item;
      if (!next) return;
      if (page === ACR_MAX_PAGES) this.failTruncated(label);
      url = allowlistedAcrNextUrl(next, host);
    }
  }

  private failTruncated(label: string): never {
    this.log.error(
      { pages: ACR_MAX_PAGES, perPage: ACR_PER_PAGE, label },
      'acr listing truncated at page cap',
    );
    throw new Error(
      `ACR listing truncated at ${ACR_MAX_PAGES * ACR_PER_PAGE} ${label} (page cap ${ACR_MAX_PAGES}); refusing to archive unseen assets`,
    );
  }

  private async exchangeAcrRefreshToken(
    loginServer: string,
    aadToken: string,
    creds: AzureCredentials,
  ): Promise<string> {
    const host = pinAcrLoginServer(loginServer);
    const url = acrOauthExchangeUrl(host);
    allowlistedAcrDataUrl(url, host);
    const body = new URLSearchParams({
      grant_type: 'access_token',
      service: host,
      tenant: creds.tenantId,
      access_token: aadToken,
    }).toString();
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new Error(`ACR oauth exchange returned ${res.status}`);
    }
    const json = (await res.json()) as { refresh_token?: unknown };
    if (typeof json.refresh_token !== 'string' || json.refresh_token.length === 0) {
      throw new Error('ACR oauth exchange did not return a refresh_token');
    }
    return json.refresh_token;
  }

  private async acrAccessToken(
    loginServer: string,
    refreshToken: string,
    scope: string,
  ): Promise<string> {
    const host = pinAcrLoginServer(loginServer);
    const url = acrOauthTokenUrl(host);
    allowlistedAcrDataUrl(url, host);
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      service: host,
      scope,
      refresh_token: refreshToken,
    }).toString();
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new Error(`ACR oauth token returned ${res.status}`);
    }
    const json = (await res.json()) as { access_token?: unknown };
    if (typeof json.access_token !== 'string' || json.access_token.length === 0) {
      throw new Error('ACR oauth token did not return an access_token');
    }
    return json.access_token;
  }

  private async getArmJson(url: string, accessToken: string, label: string): Promise<unknown> {
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
      throw new Error(`ACR ${label} ARM API returned ${res.status}`);
    }
    return res.json();
  }

  private async getAcrJson(
    url: string,
    loginServer: string,
    accessToken: string,
    label: string,
  ): Promise<{ json: unknown; next: string | undefined }> {
    const dest = allowlistedAcrDataUrl(url, loginServer);
    const res = await fetch(dest, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${accessToken}`,
      },
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new Error(`ACR ${label} API returned ${res.status}`);
    }
    const json: unknown = await res.json();
    return { json, next: nextRelFromLinkHeader(res.headers.get('link')) };
  }
}

import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { requireGcpCredentials } from './credentials';
import { exchangeGcpAccessToken } from './gcp.jwt';
import { EGRESS_GCP_API, inventoryEgressFetch } from './inventory-egress';
import {
  GCP_LOCATION_ID_RE,
  GCP_PROJECT_ID_RE,
  GCR_ALL_LOCATIONS,
  GCR_OAUTH_SCOPE,
  GCR_REPOSITORY_ID_RE,
  allowlistedGcrApiUrl,
  gcrDockerImagesUrl,
  gcrRepositoriesUrl,
  refuseTenantWritableEndpoint,
} from './gcr.egress';

export const GcrConnectorConfig = z
  .object({
    /** Project to inventory. This is a GCP project id, not an API host. */
    projectId: z.string().regex(GCP_PROJECT_ID_RE, 'must be a GCP project identifier').optional(),
    /** Alias of projectId — still an identifier, never a registry host. */
    project: z.string().regex(GCP_PROJECT_ID_RE, 'must be a GCP project identifier').optional(),
    /** Location id (`us`, `us-central1`); not a registry or API host. */
    location: z
      .string()
      .regex(GCP_LOCATION_ID_RE, 'must be an Artifact Registry location identifier')
      .optional(),
    /** Additional locations; unioned with `location`. Omit to list every location. */
    locations: z
      .array(
        z.string().regex(GCP_LOCATION_ID_RE, 'must be an Artifact Registry location identifier'),
      )
      .optional(),
    /** Optional allowlist of repository ids; omit to inventory Docker repos. */
    repositories: z
      .array(
        z
          .string()
          .regex(GCR_REPOSITORY_ID_RE, 'must be an Artifact Registry repository identifier'),
      )
      .optional(),
  })
  .superRefine((value, ctx) => {
    if (!value.projectId && !value.project) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'projectId or project is required',
        path: ['projectId'],
      });
    }
    if (value.projectId && value.project && value.projectId !== value.project) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'project and projectId must match',
        path: ['project'],
      });
    }
  });
export type GcrConnectorConfig = z.infer<typeof GcrConnectorConfig>;

export const GCR_PER_PAGE = 100;
export const GCR_MAX_PAGES = 20;

/** OCI identity is the content digest, never a mutable tag. */
export const SHA256_DIGEST_RE = /^sha256:[a-f0-9]{64}$/i;

export interface GcrRepository {
  projectId: string;
  location: string;
  name: string;
  format?: string;
}

export interface GcrImage {
  projectId: string;
  location: string;
  repository: string;
  image: string;
  digest: string;
  tags: string[];
  uri?: string;
  uploadTime?: string;
  imageSizeBytes?: string | number;
  mediaType?: string;
}

export function configuredProjectId(config: GcrConnectorConfig): string {
  return config.projectId ?? config.project!;
}

export function configuredLocations(config: GcrConnectorConfig): string[] {
  const seen = new Set<string>();
  if (config.location) seen.add(config.location);
  for (const location of config.locations ?? []) seen.add(location);
  return [...seen];
}

export function nextPageToken(json: unknown): string | undefined {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return undefined;
  const token = (json as { nextPageToken?: unknown }).nextPageToken;
  if (typeof token !== 'string') return undefined;
  const trimmed = token.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function imageDigest(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || !SHA256_DIGEST_RE.test(raw)) return undefined;
  return raw.toLowerCase();
}

export function imageTags(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((t): t is string => typeof t === 'string' && t.length > 0);
}

/**
 * Parse `projects/{p}/locations/{l}/repositories/{r}` — location/project/repo
 * are path ids, never hosts.
 */
export function parseRepositoryName(name: string): Omit<GcrRepository, 'format'> | undefined {
  const match = name.match(/^projects\/([^/]+)\/locations\/([^/]+)\/repositories\/([^/]+)$/);
  if (!match) return undefined;
  const projectId = decodeURIComponent(match[1]!);
  const location = decodeURIComponent(match[2]!);
  const repo = decodeURIComponent(match[3]!);
  if (!GCP_PROJECT_ID_RE.test(projectId)) return undefined;
  if (location === GCR_ALL_LOCATIONS || !GCP_LOCATION_ID_RE.test(location)) return undefined;
  if (!GCR_REPOSITORY_ID_RE.test(repo)) return undefined;
  return { projectId, location, name: repo };
}

/**
 * Parse `projects/{p}/locations/{l}/repositories/{r}/dockerImages/{image}@{digest}`.
 * Image path slashes are `%2F` in the resource name. Digest is required;
 * a tag-only name is not an identity.
 */
export function parseDockerImageName(name: string):
  | {
      projectId: string;
      location: string;
      repository: string;
      image: string;
      digest: string;
    }
  | undefined {
  const match = name.match(
    /^projects\/([^/]+)\/locations\/([^/]+)\/repositories\/([^/]+)\/dockerImages\/(.+)$/,
  );
  if (!match) return undefined;
  const rest = match[4]!;
  const at = rest.lastIndexOf('@');
  if (at <= 0) return undefined;
  const digest = imageDigest(rest.slice(at + 1));
  if (!digest) return undefined;
  let image: string;
  try {
    image = decodeURIComponent(rest.slice(0, at));
  } catch {
    return undefined;
  }
  if (!image || /^https?:\/\//i.test(image)) return undefined;
  const projectId = decodeURIComponent(match[1]!);
  const location = decodeURIComponent(match[2]!);
  const repository = decodeURIComponent(match[3]!);
  if (!GCP_PROJECT_ID_RE.test(projectId)) return undefined;
  if (!GCP_LOCATION_ID_RE.test(location)) return undefined;
  if (!GCR_REPOSITORY_ID_RE.test(repository)) return undefined;
  return { projectId, location, repository, image, digest };
}

export function parseRepositories(json: unknown): GcrRepository[] {
  const obj = jsonObjectOrThrow(json, 'repositories');
  const repos: GcrRepository[] = [];
  for (const raw of jsonArrayField(obj, 'repositories', 'repositories')) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as { name?: unknown; format?: unknown };
    if (typeof item.name !== 'string' || item.name.length === 0) continue;
    const parsed = parseRepositoryName(item.name);
    if (!parsed) continue;
    const format = typeof item.format === 'string' ? item.format.toUpperCase() : undefined;
    repos.push({ ...parsed, format });
  }
  return repos;
}

export function parseDockerImages(json: unknown): GcrImage[] {
  const obj = jsonObjectOrThrow(json, 'dockerImages');
  const images: GcrImage[] = [];
  for (const raw of jsonArrayField(obj, 'dockerImages', 'dockerImages')) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as {
      name?: unknown;
      uri?: unknown;
      tags?: unknown;
      uploadTime?: unknown;
      imageSizeBytes?: unknown;
      mediaType?: unknown;
    };
    if (typeof item.name !== 'string') continue;
    const parsed = parseDockerImageName(item.name);
    if (!parsed) continue;
    const image: GcrImage = {
      ...parsed,
      tags: imageTags(item.tags),
    };
    if (typeof item.uri === 'string' && item.uri.length > 0) image.uri = item.uri;
    if (typeof item.uploadTime === 'string') image.uploadTime = item.uploadTime;
    if (typeof item.imageSizeBytes === 'string' || typeof item.imageSizeBytes === 'number') {
      image.imageSizeBytes = item.imageSizeBytes;
    }
    if (typeof item.mediaType === 'string') image.mediaType = item.mediaType;
    images.push(image);
  }
  return images;
}

/**
 * Digest identity. Form:
 *   `gcr:{projectId}/{location}/{repository}/{image}@{digest}`
 *
 * projectId, location, and repository are GCP/AR identifiers (not hosts).
 * `{image}` is the docker image path inside the repository (`/` preserved).
 * Tags live in attributes so a retag does not fork assets.
 */
export function imageToAsset(image: GcrImage): UpsertAssetRequest {
  return {
    kind: 'container_image',
    externalKey: `gcr:${image.projectId}/${image.location}/${image.repository}/${image.image}@${image.digest}`,
    name: `${image.repository}/${image.image}`,
    source: 'gcr',
    exposure: 'internal',
    attributes: {
      projectId: image.projectId,
      location: image.location,
      repository: image.repository,
      image: image.image,
      digest: image.digest,
      tags: image.tags,
      uri: image.uri ?? null,
      uploadTime: image.uploadTime ?? null,
      imageSizeBytes: image.imageSizeBytes ?? null,
      mediaType: image.mediaType ?? null,
    },
  };
}

function jsonObjectOrThrow(json: unknown, label: string): Record<string, unknown> {
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    throw new Error(`GCR ${label} listing was not a JSON object — refusing incomplete inventory`);
  }
  return json as Record<string, unknown>;
}

function jsonArrayField(obj: Record<string, unknown>, field: string, label: string): unknown[] {
  const value = obj[field];
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`GCR ${label} listing was not a JSON array — refusing incomplete inventory`);
  }
  return value;
}

/**
 * Container-image inventory via Google Artifact Registry (`ListRepositories`
 * + `ListDockerImages`). Same persistence path as ECR/GHCR: discover →
 * UpsertAssetRequest → scheduler upsert + archiveStale scoped per
 * integrationId.
 *
 * Hosts are hardcoded to allowlisted `artifactregistry.googleapis.com` (and
 * `oauth2.googleapis.com` for the token). Tenant config cannot set a
 * registry/API host. Credentials are platform-operated `env:GCP_*` and fail
 * closed when missing — there is no public-listing fallback.
 *
 * Identity is the image digest. Tags live in attributes so a retag does not
 * fork assets. This connector does not pull layers or fetch OCI blobs —
 * inventory is the Artifact Registry JSON API only.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — Artifact Registry
 * list APIs do not offer a reliable incremental window for this inventory.
 */
@Injectable()
export class GcrConnector implements AssetConnector {
  readonly provider = 'gcr';
  readonly assetKinds = ['container_image'];
  private readonly log = rootLogger.child({ component: 'gcr-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantWritableEndpoint(ctx.config);
    const config = GcrConnectorConfig.parse(ctx.config);
    const creds = requireGcpCredentials(ctx.credentialRef);
    const accessToken = await exchangeGcpAccessToken(creds, GCR_OAUTH_SCOPE);
    const projectId = configuredProjectId(config);
    const locations = configuredLocations(config);
    const allow = config.repositories?.length ? new Set(config.repositories) : null;

    let seen = 0;
    const yielded = new Set<string>();
    const listLocations = locations.length > 0 ? locations : [GCR_ALL_LOCATIONS];

    for (const location of listLocations) {
      for await (const repo of this.listRepositories(projectId, location, accessToken)) {
        if (allow && !allow.has(repo.name)) continue;
        if (repo.format && repo.format !== 'DOCKER') continue;
        if (repo.projectId !== projectId) continue;

        for await (const image of this.listDockerImages(
          projectId,
          repo.location,
          repo.name,
          accessToken,
        )) {
          if (image.projectId !== projectId) continue;
          const asset = imageToAsset(image);
          if (yielded.has(asset.externalKey)) continue;
          yielded.add(asset.externalKey);
          seen += 1;
          yield asset;
        }
      }
    }

    this.log.info({ projectId, locations: listLocations, images: seen }, 'gcr discovery complete');
  }

  private async *listRepositories(
    projectId: string,
    location: string,
    accessToken: string,
  ): AsyncIterable<GcrRepository> {
    yield* this.pagedGet(
      gcrRepositoriesUrl(projectId, location),
      accessToken,
      (json) => parseRepositories(json),
      'repositories',
    );
  }

  private async *listDockerImages(
    projectId: string,
    location: string,
    repository: string,
    accessToken: string,
  ): AsyncIterable<GcrImage> {
    yield* this.pagedGet(
      gcrDockerImagesUrl(projectId, location, repository),
      accessToken,
      (json) => parseDockerImages(json),
      `dockerImages for ${repository}`,
    );
  }

  /**
   * Complete-signal is missing nextPageToken, not page length. A last page of
   * GCR_PER_PAGE with no token succeeds. Only a leftover nextPageToken after
   * the cap is truncated / fail-closed (so archiveStale cannot run on a
   * partial list).
   */
  private async *pagedGet<T>(
    baseUrl: string,
    accessToken: string,
    mapPage: (json: unknown) => T[],
    label: string,
  ): AsyncIterable<T> {
    let token: string | undefined;
    for (let page = 1; page <= GCR_MAX_PAGES; page++) {
      const json = await this.getJson(pagedUrl(baseUrl, token), accessToken, label);
      for (const item of mapPage(json)) yield item;
      token = nextPageToken(json);
      if (!token) return;
      if (page === GCR_MAX_PAGES) this.failTruncated(label);
    }
  }

  private failTruncated(label: string): never {
    this.log.error(
      { pages: GCR_MAX_PAGES, perPage: GCR_PER_PAGE, label },
      'gcr listing truncated at page cap',
    );
    throw new Error(
      `GCR listing truncated at ${GCR_MAX_PAGES * GCR_PER_PAGE} ${label} (page cap ${GCR_MAX_PAGES}); refusing to archive unseen assets`,
    );
  }

  private async getJson(url: string, accessToken: string, label: string): Promise<unknown> {
    // Belt: never send the bearer token off artifactregistry.googleapis.com.
    allowlistedGcrApiUrl(url);
    const res = await inventoryEgressFetch(EGRESS_GCP_API, url, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${accessToken}`,
      },
    });
    if (!res.ok) {
      throw new Error(`GCR ${label} API returned ${res.status}`);
    }
    return res.json();
  }
}

function pagedUrl(baseUrl: string, pageToken: string | undefined): string {
  const url = new URL(allowlistedGcrApiUrl(baseUrl));
  url.searchParams.set('pageSize', String(GCR_PER_PAGE));
  if (pageToken) url.searchParams.set('pageToken', pageToken);
  return allowlistedGcrApiUrl(url.href);
}

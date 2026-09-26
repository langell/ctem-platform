import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { requireQuayToken } from './credentials';
import {
  QUAY_NAMESPACE_RE,
  QUAY_REPOSITORY_RE,
  allowlistedQuayApiUrl,
  quayRepositoriesUrl,
  quayTagsUrl,
  refuseTenantWritableEndpoint,
} from './quay.egress';
import { EGRESS_QUAY_API, inventoryEgressFetch } from './inventory-egress';

export const QuayConnectorConfig = z.object({
  /** Quay.org / user id whose repositories to inventory. Never a host. */
  namespace: z.string().regex(QUAY_NAMESPACE_RE, 'must be a Quay organization or user identifier'),
  /** Optional allowlist of repository names; omit to inventory everything. */
  repositories: z
    .array(z.string().regex(QUAY_REPOSITORY_RE, 'must be a Quay repository identifier'))
    .optional(),
});
export type QuayConnectorConfig = z.infer<typeof QuayConnectorConfig>;

export const QUAY_PER_PAGE = 100;
export const QUAY_MAX_PAGES = 20;

/** OCI identity is the content digest, never a mutable tag. */
export const SHA256_DIGEST_RE = /^sha256:[a-f0-9]{64}$/i;

export interface QuayRepository {
  namespace: string;
  name: string;
  isPublic?: boolean;
  description?: string;
}

export interface QuayTag {
  digest: string;
  name?: string;
  lastModified?: string;
  size?: number;
  isManifestList?: boolean;
}

export interface QuayImage {
  namespace: string;
  repository: string;
  digest: string;
  tags: string[];
  isPublic?: boolean;
  lastModified?: string;
  size?: number;
  isManifestList?: boolean;
}

export function imageDigest(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || !SHA256_DIGEST_RE.test(raw)) return undefined;
  return raw.toLowerCase();
}

export function nextPageToken(json: unknown): string | undefined {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return undefined;
  const token = (json as { next_page?: unknown }).next_page;
  if (typeof token !== 'string') return undefined;
  const trimmed = token.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/** Complete-signal for tag listing is has_additional !== true, not page length. */
export function hasAdditionalTags(json: unknown): boolean {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return false;
  return (json as { has_additional?: unknown }).has_additional === true;
}

export function parseRepositories(json: unknown): QuayRepository[] {
  const obj = jsonObjectOrThrow(json, 'repositories');
  const repos: QuayRepository[] = [];
  for (const raw of jsonArrayField(obj, 'repositories', 'repositories')) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as {
      namespace?: unknown;
      name?: unknown;
      is_public?: unknown;
      description?: unknown;
      kind?: unknown;
      state?: unknown;
    };
    if (typeof item.name !== 'string' || !QUAY_REPOSITORY_RE.test(item.name)) continue;
    if (typeof item.namespace !== 'string' || !QUAY_NAMESPACE_RE.test(item.namespace)) continue;
    if (item.kind != null && item.kind !== 'image') continue;
    if (item.state != null && item.state !== 'NORMAL') continue;
    const repo: QuayRepository = { namespace: item.namespace, name: item.name };
    if (typeof item.is_public === 'boolean') repo.isPublic = item.is_public;
    if (typeof item.description === 'string') repo.description = item.description;
    repos.push(repo);
  }
  return repos;
}

export function parseTags(json: unknown): QuayTag[] {
  const obj = jsonObjectOrThrow(json, 'tags');
  const tags: QuayTag[] = [];
  for (const raw of jsonArrayField(obj, 'tags', 'tags')) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as {
      name?: unknown;
      manifest_digest?: unknown;
      last_modified?: unknown;
      size?: unknown;
      is_manifest_list?: unknown;
    };
    const digest = imageDigest(item.manifest_digest);
    if (!digest) continue;
    const tag: QuayTag = { digest };
    if (typeof item.name === 'string' && item.name.length > 0) tag.name = item.name;
    if (typeof item.last_modified === 'string') tag.lastModified = item.last_modified;
    if (typeof item.size === 'number') tag.size = item.size;
    if (typeof item.is_manifest_list === 'boolean') tag.isManifestList = item.is_manifest_list;
    tags.push(tag);
  }
  return tags;
}

/**
 * Digest identity. Form:
 *   `quay:{namespace}/{repository}@sha256:…`
 *
 * namespace and repository are Quay identifiers (not hosts). Digest is
 * required; tags live in attributes so a retag does not fork assets.
 */
export function imageToAsset(image: QuayImage): UpsertAssetRequest {
  return {
    kind: 'container_image',
    externalKey: `quay:${image.namespace}/${image.repository}@${image.digest}`,
    name: `${image.namespace}/${image.repository}`,
    source: 'quay',
    exposure:
      image.isPublic === true
        ? 'internet_facing'
        : image.isPublic === false
          ? 'internal'
          : 'unknown',
    attributes: {
      namespace: image.namespace,
      repository: image.repository,
      digest: image.digest,
      tags: image.tags,
      isPublic: image.isPublic ?? null,
      lastModified: image.lastModified ?? null,
      size: image.size ?? null,
      isManifestList: image.isManifestList ?? null,
    },
  };
}

function jsonObjectOrThrow(json: unknown, label: string): Record<string, unknown> {
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    throw new Error(`Quay ${label} listing was not a JSON object — refusing incomplete inventory`);
  }
  return json as Record<string, unknown>;
}

function jsonArrayField(obj: Record<string, unknown>, field: string, label: string): unknown[] {
  const value = obj[field];
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`Quay ${label} listing was not a JSON array — refusing incomplete inventory`);
  }
  return value;
}

/**
 * Container-image inventory via Quay.io REST (`/api/v1/repository` +
 * `/api/v1/repository/{namespace}/{repository}/tag`). Same persistence path
 * as GHCR/ECR/GCR/ACR: discover → UpsertAssetRequest → scheduler upsert +
 * archiveStale scoped per integrationId.
 *
 * Hosts are hardcoded to allowlisted `quay.io` HTTPS/443 under `/api/v1/`.
 * Tenant config cannot set a registry/API host (no self-hosted Quay this
 * slice). Credentials are platform-operated `env:QUAY_*` and fail closed
 * when missing — there is no public-listing / anonymous fallback.
 *
 * Identity is the image digest. Tags live in attributes so a retag does not
 * fork assets. This connector does not pull layers or fetch OCI blobs —
 * inventory is Quay JSON API metadata only.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — Quay list APIs
 * do not offer a reliable incremental window for this inventory.
 */
@Injectable()
export class QuayConnector implements AssetConnector {
  readonly provider = 'quay';
  readonly assetKinds = ['container_image'];
  private readonly log = rootLogger.child({ component: 'quay-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantWritableEndpoint(ctx.config);
    const config = QuayConnectorConfig.parse(ctx.config);
    const token = requireQuayToken(ctx.credentialRef);
    const allow = config.repositories?.length ? new Set(config.repositories) : null;

    let seen = 0;
    const yielded = new Set<string>();

    for await (const repo of this.listRepositories(config.namespace, token)) {
      if (allow && !allow.has(repo.name)) continue;
      if (repo.namespace.toLowerCase() !== config.namespace.toLowerCase()) continue;

      const byDigest = new Map<
        string,
        { tags: string[]; lastModified?: string; size?: number; isManifestList?: boolean }
      >();
      for await (const tag of this.listTags(config.namespace, repo.name, token)) {
        const existing = byDigest.get(tag.digest);
        if (existing) {
          if (tag.name && !existing.tags.includes(tag.name)) existing.tags.push(tag.name);
          continue;
        }
        byDigest.set(tag.digest, {
          tags: tag.name ? [tag.name] : [],
          lastModified: tag.lastModified,
          size: tag.size,
          isManifestList: tag.isManifestList,
        });
      }

      for (const [digest, info] of byDigest) {
        const asset = imageToAsset({
          namespace: config.namespace,
          repository: repo.name,
          digest,
          tags: info.tags,
          isPublic: repo.isPublic,
          lastModified: info.lastModified,
          size: info.size,
          isManifestList: info.isManifestList,
        });
        if (yielded.has(asset.externalKey)) continue;
        yielded.add(asset.externalKey);
        seen += 1;
        yield asset;
      }
    }

    this.log.info({ namespace: config.namespace, images: seen }, 'quay discovery complete');
  }

  private async *listRepositories(
    namespace: string,
    token: string,
  ): AsyncIterable<QuayRepository> {
    let next: string | undefined;
    for (let page = 1; page <= QUAY_MAX_PAGES; page++) {
      const json = await this.getJson(quayRepositoriesUrl(namespace, next), token, 'repositories');
      for (const item of parseRepositories(json)) yield item;
      next = nextPageToken(json);
      if (!next) return;
      if (page === QUAY_MAX_PAGES) this.failTruncated('repositories');
    }
  }

  /**
   * Complete-signal is has_additional !== true, not page length. A last page
   * of QUAY_PER_PAGE with has_additional false succeeds. Only leftover
   * has_additional after the cap is truncated / fail-closed (so archiveStale
   * cannot run on a partial list).
   */
  private async *listTags(
    namespace: string,
    repository: string,
    token: string,
  ): AsyncIterable<QuayTag> {
    for (let page = 1; page <= QUAY_MAX_PAGES; page++) {
      const json = await this.getJson(
        quayTagsUrl(namespace, repository, page),
        token,
        `tags for ${repository}`,
      );
      for (const item of parseTags(json)) yield item;
      if (!hasAdditionalTags(json)) return;
      if (page === QUAY_MAX_PAGES) this.failTruncated(`tags for ${repository}`);
    }
  }

  private failTruncated(label: string): never {
    this.log.error(
      { pages: QUAY_MAX_PAGES, perPage: QUAY_PER_PAGE, label },
      'quay listing truncated at page cap',
    );
    throw new Error(
      `Quay listing truncated at ${QUAY_MAX_PAGES * QUAY_PER_PAGE} ${label} (page cap ${QUAY_MAX_PAGES}); refusing to archive unseen assets`,
    );
  }

  private async getJson(url: string, token: string, label: string): Promise<unknown> {
    // Belt: never send the bearer token off quay.io /api/v1 even if a caller built `url`.
    const dest = allowlistedQuayApiUrl(url);
    const res = await inventoryEgressFetch(EGRESS_QUAY_API, dest, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        'user-agent': 'ctem-platform',
        authorization: `Bearer ${token}`,
      },
    });
    if (!res.ok) {
      throw new Error(`Quay ${label} API returned ${res.status}`);
    }
    return res.json();
  }
}

import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { requireDockerhubCredentials, type DockerhubCredentials } from './credentials';
import {
  DOCKERHUB_NAMESPACE_RE,
  DOCKERHUB_REPOSITORY_RE,
  allowlistedDockerhubUrl,
  dockerhubLoginUrl,
  dockerhubRepositoriesUrl,
  dockerhubTagsUrl,
  refuseTenantWritableEndpoint,
} from './dockerhub.egress';
import { EGRESS_DOCKERHUB_API, inventoryEgressFetch } from './inventory-egress';

export const DockerhubConnectorConfig = z.object({
  /** Docker Hub org or user id whose repositories to inventory. Never a host. */
  namespace: z.string().regex(DOCKERHUB_NAMESPACE_RE, 'must be a Docker Hub namespace identifier'),
  /** Optional allowlist of repository ids; omit to inventory everything. */
  repositories: z
    .array(
      z.string().regex(DOCKERHUB_REPOSITORY_RE, 'must be a Docker Hub repository identifier'),
    )
    .optional(),
});
export type DockerhubConnectorConfig = z.infer<typeof DockerhubConnectorConfig>;

export const DOCKERHUB_PER_PAGE = 100;
export const DOCKERHUB_MAX_PAGES = 20;

/** OCI identity is the content digest, never a mutable tag. */
export const SHA256_DIGEST_RE = /^sha256:[a-f0-9]{64}$/i;

export interface DockerhubRepository {
  name: string;
  namespace?: string;
  isPrivate?: boolean;
}

export interface DockerhubImage {
  namespace: string;
  repository: string;
  digest: string;
  tags: string[];
  isPrivate?: boolean;
}

export function imageDigest(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || !SHA256_DIGEST_RE.test(raw)) return undefined;
  return raw.toLowerCase();
}

/**
 * Prefer the tag-level digest (index identity). If Hub omitted it, unique
 * `images[].digest` values are still digest identities — never the tag name.
 */
export function tagDigests(raw: unknown): string[] {
  if (!raw || typeof raw !== 'object') return [];
  const item = raw as { digest?: unknown; images?: unknown };
  const top = imageDigest(item.digest);
  if (top) return [top];
  if (!Array.isArray(item.images)) return [];
  const seen = new Set<string>();
  const digests: string[] = [];
  for (const image of item.images) {
    if (!image || typeof image !== 'object') continue;
    const digest = imageDigest((image as { digest?: unknown }).digest);
    if (!digest || seen.has(digest)) continue;
    seen.add(digest);
    digests.push(digest);
  }
  return digests;
}

/** Complete-signal is a missing `next`, not page length. */
export function nextUrl(json: unknown): string | undefined {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return undefined;
  const next = (json as { next?: unknown }).next;
  if (typeof next !== 'string') return undefined;
  const trimmed = next.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function parseRepositories(json: unknown): DockerhubRepository[] {
  const obj = jsonObjectOrThrow(json, 'repositories');
  const repos: DockerhubRepository[] = [];
  for (const raw of jsonArrayField(obj, 'results', 'repositories')) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as {
      name?: unknown;
      namespace?: unknown;
      user?: unknown;
      is_private?: unknown;
      repository_type?: unknown;
    };
    if (typeof item.name !== 'string' || !DOCKERHUB_REPOSITORY_RE.test(item.name)) continue;
    if (item.repository_type != null && item.repository_type !== 'image') continue;
    const namespace =
      typeof item.namespace === 'string'
        ? item.namespace
        : typeof item.user === 'string'
          ? item.user
          : undefined;
    repos.push({
      name: item.name,
      namespace,
      isPrivate: typeof item.is_private === 'boolean' ? item.is_private : undefined,
    });
  }
  return repos;
}

export function parseTags(json: unknown): Array<{ name: string; digests: string[] }> {
  const obj = jsonObjectOrThrow(json, 'tags');
  const tags: Array<{ name: string; digests: string[] }> = [];
  for (const raw of jsonArrayField(obj, 'results', 'tags')) {
    if (!raw || typeof raw !== 'object') continue;
    const item = raw as { name?: unknown };
    if (typeof item.name !== 'string' || item.name.length === 0) continue;
    const digests = tagDigests(raw);
    if (digests.length === 0) continue;
    tags.push({ name: item.name, digests });
  }
  return tags;
}

export function imageToAsset(image: DockerhubImage): UpsertAssetRequest {
  return {
    kind: 'container_image',
    externalKey: `dockerhub:${image.namespace}/${image.repository}@${image.digest}`,
    name: `${image.namespace}/${image.repository}`,
    source: 'dockerhub',
    exposure:
      image.isPrivate === true ? 'internal' : image.isPrivate === false ? 'internet_facing' : 'unknown',
    attributes: {
      namespace: image.namespace,
      repository: image.repository,
      digest: image.digest,
      tags: image.tags,
      isPrivate: image.isPrivate ?? null,
    },
  };
}

function jsonObjectOrThrow(json: unknown, label: string): Record<string, unknown> {
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    throw new Error(
      `Docker Hub ${label} listing was not a JSON object — refusing incomplete inventory`,
    );
  }
  return json as Record<string, unknown>;
}

function jsonArrayField(obj: Record<string, unknown>, field: string, label: string): unknown[] {
  const value = obj[field];
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(
      `Docker Hub ${label} listing was not a JSON array — refusing incomplete inventory`,
    );
  }
  return value;
}

/**
 * Container-image inventory via Docker Hub Hub API (repository list + tag
 * digest metadata). Same persistence path as GHCR/ECR/GCR/ACR: discover →
 * UpsertAssetRequest → scheduler upsert + archiveStale scoped per
 * integrationId.
 *
 * Hosts are hardcoded to allowlisted `hub.docker.com`. Tenant config cannot
 * set a registry/API host. Credentials are platform-operated `env:DOCKERHUB_*`
 * and fail closed when missing — there is no public-listing fallback.
 *
 * Identity is the image digest. Tags live in attributes so a retag does not
 * fork assets. This connector does not pull layers or fetch OCI blobs —
 * inventory is Hub listing only.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — Hub list
 * endpoints do not offer a reliable incremental window for this inventory.
 */
@Injectable()
export class DockerhubConnector implements AssetConnector {
  readonly provider = 'dockerhub';
  readonly assetKinds = ['container_image'];
  private readonly log = rootLogger.child({ component: 'dockerhub-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantWritableEndpoint(ctx.config);
    const config = DockerhubConnectorConfig.parse(ctx.config);
    const creds = requireDockerhubCredentials(ctx.credentialRef);
    const token = await this.login(creds);
    const allow = config.repositories?.length ? new Set(config.repositories) : null;

    let seen = 0;
    const yielded = new Set<string>();

    for await (const repo of this.listRepositories(config, token)) {
      if (allow && !allow.has(repo.name)) continue;
      if (repo.namespace && repo.namespace.toLowerCase() !== config.namespace.toLowerCase()) {
        continue;
      }

      const tagsByDigest = new Map<string, string[]>();
      for await (const tag of this.listTags(config, token, repo.name)) {
        for (const digest of tag.digests) {
          const tags = tagsByDigest.get(digest) ?? [];
          if (!tags.includes(tag.name)) tags.push(tag.name);
          tagsByDigest.set(digest, tags);
        }
      }

      for (const [digest, tags] of tagsByDigest) {
        const asset = imageToAsset({
          namespace: config.namespace,
          repository: repo.name,
          digest,
          tags,
          isPrivate: repo.isPrivate,
        });
        if (yielded.has(asset.externalKey)) continue;
        yielded.add(asset.externalKey);
        seen += 1;
        yield asset;
      }
    }

    this.log.info({ namespace: config.namespace, images: seen }, 'dockerhub discovery complete');
  }

  private async *listRepositories(
    config: DockerhubConnectorConfig,
    token: string,
  ): AsyncIterable<DockerhubRepository> {
    yield* this.pagedGet(
      dockerhubRepositoriesUrl(config.namespace),
      token,
      (json) => parseRepositories(json),
      'repositories',
    );
  }

  private async *listTags(
    config: DockerhubConnectorConfig,
    token: string,
    repository: string,
  ): AsyncIterable<{ name: string; digests: string[] }> {
    yield* this.pagedGet(
      dockerhubTagsUrl(config.namespace, repository),
      token,
      (json) => parseTags(json),
      `tags for ${repository}`,
    );
  }

  /**
   * Complete-signal is missing JSON `next`, not page length. A last page of
   * DOCKERHUB_PER_PAGE with no next succeeds. Only a leftover next after the
   * cap is truncated / fail-closed (so archiveStale cannot run on a partial
   * list). next is a full URL — allowlist before GET.
   */
  private async *pagedGet<T>(
    firstUrl: string,
    token: string,
    mapPage: (json: unknown) => T[],
    label: string,
  ): AsyncIterable<T> {
    let url = firstUrl;
    for (let page = 1; page <= DOCKERHUB_MAX_PAGES; page++) {
      const json = await this.getJson(url, token, label);
      for (const item of mapPage(json)) yield item;
      const next = nextUrl(json);
      if (!next) return;
      if (page === DOCKERHUB_MAX_PAGES) this.failTruncated(label);
      url = allowlistedDockerhubUrl(next);
    }
  }

  private failTruncated(label: string): never {
    this.log.error(
      { pages: DOCKERHUB_MAX_PAGES, perPage: DOCKERHUB_PER_PAGE, label },
      'dockerhub listing truncated at page cap',
    );
    throw new Error(
      `Docker Hub listing truncated at ${DOCKERHUB_MAX_PAGES * DOCKERHUB_PER_PAGE} ${label} (page cap ${DOCKERHUB_MAX_PAGES}); refusing to archive unseen assets`,
    );
  }

  private async login(creds: DockerhubCredentials): Promise<string> {
    const dest = allowlistedDockerhubUrl(dockerhubLoginUrl());
    const res = await inventoryEgressFetch(EGRESS_DOCKERHUB_API, dest, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'user-agent': 'ctem-platform',
      },
      body: JSON.stringify({ username: creds.username, password: creds.token }),
      redirect: 'error',
    });
    if (!res.ok) {
      throw new Error(`Docker Hub login API returned ${res.status}`);
    }
    const json: unknown = await res.json();
    const token =
      json && typeof json === 'object' ? (json as { token?: unknown }).token : undefined;
    if (typeof token !== 'string' || token.trim().length === 0) {
      throw new Error('Docker Hub login API did not return a token');
    }
    return token.trim();
  }

  private async getJson(url: string, token: string, label: string): Promise<unknown> {
    // Belt: never send the Hub JWT off hub.docker.com even if a caller built `url`.
    const dest = allowlistedDockerhubUrl(url);
    const res = await inventoryEgressFetch(EGRESS_DOCKERHUB_API, dest, {
      method: 'GET',
      headers: {
        accept: 'application/json',
        'user-agent': 'ctem-platform',
        authorization: `JWT ${token}`,
      },
      redirect: 'error',
    });
    if (!res.ok) {
      throw new Error(`Docker Hub ${label} API returned ${res.status}`);
    }
    return res.json();
  }
}

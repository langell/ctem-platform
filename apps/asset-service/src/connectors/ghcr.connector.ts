import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { requireGithubToken } from './credentials';
import {
  allowlistedGithubApiUrl,
  ghcrPackageVersionsUrl,
  ghcrPackagesUrl,
  nextRelFromLinkHeader,
  refuseTenantWritableEndpoint,
} from './ghcr.egress';

export const GhcrConnectorConfig = z.object({
  /** User or organization whose GHCR container packages to inventory. */
  owner: z.string().min(1),
  /** Required so an org integration cannot silently hit /users/:owner/packages. */
  ownerType: z.enum(['user', 'org']),
  /** Optional allowlist of package names; omit to inventory everything. */
  packages: z.array(z.string().min(1)).optional(),
});
export type GhcrConnectorConfig = z.infer<typeof GhcrConnectorConfig>;

export const GHCR_PER_PAGE = 100;
export const GHCR_MAX_PAGES = 20;

/** OCI/GHCR identity is the content digest, never a mutable tag. */
export const SHA256_DIGEST_RE = /^sha256:[a-f0-9]{64}$/i;

export interface GhcrPackage {
  name: string;
  visibility?: string;
  htmlUrl?: string;
  ownerLogin?: string;
}

export interface GhcrImage {
  owner: string;
  packageName: string;
  digest: string;
  tags: string[];
  visibility?: string;
  htmlUrl?: string;
}

export function versionDigest(raw: unknown): string | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const name = (raw as { name?: unknown }).name;
  if (typeof name !== 'string' || !SHA256_DIGEST_RE.test(name)) return undefined;
  return name.toLowerCase();
}

export function versionTags(raw: unknown): string[] {
  if (!raw || typeof raw !== 'object') return [];
  const metadata = (raw as { metadata?: unknown }).metadata;
  if (!metadata || typeof metadata !== 'object') return [];
  const container = (metadata as { container?: unknown }).container;
  if (!container || typeof container !== 'object') return [];
  const tags = (container as { tags?: unknown }).tags;
  if (!Array.isArray(tags)) return [];
  return tags.filter((t): t is string => typeof t === 'string' && t.length > 0);
}

export function parsePackages(json: unknown): GhcrPackage[] {
  if (!Array.isArray(json)) return [];
  const packages: GhcrPackage[] = [];
  for (const raw of json) {
    if (!raw || typeof raw !== 'object') continue;
    const pkg = raw as {
      name?: unknown;
      package_type?: unknown;
      visibility?: unknown;
      html_url?: unknown;
      owner?: { login?: unknown };
    };
    if (typeof pkg.name !== 'string' || pkg.name.length === 0) continue;
    if (pkg.package_type != null && pkg.package_type !== 'container') continue;
    packages.push({
      name: pkg.name,
      visibility: typeof pkg.visibility === 'string' ? pkg.visibility : undefined,
      htmlUrl: typeof pkg.html_url === 'string' ? pkg.html_url : undefined,
      ownerLogin: typeof pkg.owner?.login === 'string' ? pkg.owner.login : undefined,
    });
  }
  return packages;
}

export function parseVersions(json: unknown): Array<{ digest: string; tags: string[] }> {
  if (!Array.isArray(json)) return [];
  const versions: Array<{ digest: string; tags: string[] }> = [];
  for (const raw of json) {
    if (!raw || typeof raw !== 'object') continue;
    if ((raw as { deleted_at?: unknown }).deleted_at) continue;
    const digest = versionDigest(raw);
    if (!digest) continue;
    versions.push({ digest, tags: versionTags(raw) });
  }
  return versions;
}

export function imageToAsset(image: GhcrImage): UpsertAssetRequest {
  return {
    kind: 'container_image',
    externalKey: `ghcr:${image.owner}/${image.packageName}@${image.digest}`,
    name: `${image.owner}/${image.packageName}`,
    source: 'ghcr',
    exposure:
      image.visibility === 'public'
        ? 'internet_facing'
        : image.visibility === 'private'
          ? 'internal'
          : 'unknown',
    attributes: {
      owner: image.owner,
      package: image.packageName,
      digest: image.digest,
      tags: image.tags,
      visibility: image.visibility ?? null,
      htmlUrl: image.htmlUrl ?? null,
      packageType: 'container',
    },
  };
}

function jsonArrayOrThrow(json: unknown, label: string): unknown[] {
  if (!Array.isArray(json)) {
    throw new Error(`GHCR ${label} listing was not a JSON array — refusing incomplete inventory`);
  }
  return json;
}

/**
 * Container-image inventory via GitHub Packages REST (`package_type=container`).
 * Same persistence path as AWS/GCP/Azure: discover → UpsertAssetRequest →
 * scheduler upsert + archiveStale scoped per integrationId.
 *
 * Hosts are hardcoded to allowlisted `api.github.com`. Tenant config cannot
 * set a registry/API host. Credentials are platform-operated `env:GITHUB_*`
 * and fail closed when missing — there is no public-listing fallback.
 *
 * Identity is the image digest. Tags live in attributes so a retag does not
 * fork assets. This connector does not pull layers or fetch OCI blobs —
 * inventory is Packages REST only.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — Packages list
 * endpoints do not offer a reliable incremental window for this inventory.
 */
@Injectable()
export class GhcrConnector implements AssetConnector {
  readonly provider = 'ghcr';
  readonly assetKinds = ['container_image'];
  private readonly log = rootLogger.child({ component: 'ghcr-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantWritableEndpoint(ctx.config);
    const config = GhcrConnectorConfig.parse(ctx.config);
    const token = requireGithubToken(ctx.credentialRef);
    const allow = config.packages?.length ? new Set(config.packages) : null;

    let seen = 0;
    const yielded = new Set<string>();

    for await (const pkg of this.listPackages(config, token)) {
      if (allow && !allow.has(pkg.name)) continue;
      if (pkg.ownerLogin && pkg.ownerLogin.toLowerCase() !== config.owner.toLowerCase()) continue;

      for await (const version of this.listVersions(config, token, pkg.name)) {
        const asset = imageToAsset({
          owner: config.owner,
          packageName: pkg.name,
          digest: version.digest,
          tags: version.tags,
          visibility: pkg.visibility,
          htmlUrl: pkg.htmlUrl,
        });
        if (yielded.has(asset.externalKey)) continue;
        yielded.add(asset.externalKey);
        seen += 1;
        yield asset;
      }
    }

    this.log.info({ owner: config.owner, images: seen }, 'ghcr discovery complete');
  }

  private async *listPackages(
    config: GhcrConnectorConfig,
    token: string,
  ): AsyncIterable<GhcrPackage> {
    yield* this.pagedGet(
      ghcrPackagesUrl(config.owner, config.ownerType),
      token,
      (json) => parsePackages(jsonArrayOrThrow(json, 'packages')),
      'packages',
    );
  }

  private async *listVersions(
    config: GhcrConnectorConfig,
    token: string,
    packageName: string,
  ): AsyncIterable<{ digest: string; tags: string[] }> {
    yield* this.pagedGet(
      ghcrPackageVersionsUrl(config.owner, config.ownerType, packageName),
      token,
      (json) => parseVersions(jsonArrayOrThrow(json, 'versions')),
      `versions for ${packageName}`,
    );
  }

  /**
   * Complete-signal is missing Link rel=next or an empty page, not page
   * length. A last page of GHCR_PER_PAGE with no next succeeds. Only a
   * leftover next after the cap is truncated / fail-closed (so archiveStale
   * cannot run on a partial list). next is a full URL — allowlist before GET.
   */
  private async *pagedGet<T>(
    firstUrl: string,
    token: string,
    mapPage: (json: unknown) => T[],
    label: string,
  ): AsyncIterable<T> {
    let url = firstUrl;
    for (let page = 1; page <= GHCR_MAX_PAGES; page++) {
      const { json, next } = await this.getJson(url, token, label);
      const raw = jsonArrayOrThrow(json, label);
      if (raw.length === 0) return;
      for (const item of mapPage(json)) yield item;
      if (!next) return;
      if (page === GHCR_MAX_PAGES) this.failTruncated(label);
      url = allowlistedGithubApiUrl(next);
    }
  }

  private failTruncated(label: string): never {
    this.log.error(
      { pages: GHCR_MAX_PAGES, perPage: GHCR_PER_PAGE, label },
      'ghcr listing truncated at page cap',
    );
    throw new Error(
      `GHCR listing truncated at ${GHCR_MAX_PAGES * GHCR_PER_PAGE} ${label} (page cap ${GHCR_MAX_PAGES}); refusing to archive unseen assets`,
    );
  }

  private async getJson(
    url: string,
    token: string,
    label: string,
  ): Promise<{ json: unknown; next: string | undefined }> {
    // Belt: never send the bearer token off api.github.com even if a caller built `url`.
    const dest = allowlistedGithubApiUrl(url);
    const res = await fetch(dest, {
      method: 'GET',
      headers: {
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        'user-agent': 'ctem-platform',
        authorization: `Bearer ${token}`,
      },
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) {
      throw new Error(`GHCR ${label} API returned ${res.status}`);
    }
    const json: unknown = await res.json();
    return { json, next: nextRelFromLinkHeader(res.headers.get('link')) };
  }
}

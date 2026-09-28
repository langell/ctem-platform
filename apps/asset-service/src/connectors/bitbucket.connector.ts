import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { requireBitbucketToken } from './credentials';
import {
  BITBUCKET_ID_RE,
  allowlistedBitbucketApiUrl,
  assertBitbucketRepoSlug,
  assertBitbucketWorkspace,
  bitbucketCloneUrl,
  bitbucketHtmlUrl,
  bitbucketRepositoriesUrl,
  refuseTenantWritableEndpoint,
} from './bitbucket.egress';
import { EGRESS_BITBUCKET_API, inventoryEgressFetch } from './inventory-egress';

export interface BitbucketRepo {
  name?: string;
  slug?: string;
  full_name?: string;
  description?: string | null;
  is_private?: boolean;
  language?: string | null;
  updated_on?: string;
  mainbranch?: { name?: string } | null;
  /** Present on forks. Not a host. */
  parent?: unknown;
  /** Cloud list payloads may omit this; Data Center archive is out of this slice. */
  archived?: boolean;
  is_archived?: boolean;
  workspace?: { slug?: string };
  links?: {
    html?: { href?: string };
    clone?: Array<{ href?: string; name?: string }>;
  };
}

export const BitbucketConnectorConfig = z.object({
  /** Bitbucket Cloud workspace id/slug. An identifier, never a host. */
  workspace: z.string().regex(BITBUCKET_ID_RE, 'must be a Bitbucket workspace id'),
  /** Optional allowlist of repo slugs; omit to inventory the workspace. */
  repos: z.array(z.string().regex(BITBUCKET_ID_RE, 'must be a Bitbucket repo slug')).optional(),
  includeArchived: z.boolean().optional(),
  includeForks: z.boolean().optional(),
});
export type BitbucketConnectorConfig = z.infer<typeof BitbucketConnectorConfig>;

export const BITBUCKET_PER_PAGE = 100;
export const BITBUCKET_MAX_PAGES = 20;

/**
 * Pure mapping. `externalKey` is `bitbucket:{workspace}/{repo_slug}`.
 * `cloneUrl` and `htmlUrl` are synthesized on bitbucket.org — never
 * `links.html.href` or clone hrefs from the payload.
 */
export function repoToAsset(repo: BitbucketRepo, workspace: string): UpsertAssetRequest {
  const ws = assertBitbucketWorkspace(workspace);
  const slug = assertBitbucketRepoSlug(requiredSlug(repo));
  if (typeof repo.is_private !== 'boolean') {
    throw new Error(
      `Refusing Bitbucket repository '${ws}/${slug}' without a boolean is_private — refusing incomplete inventory`,
    );
  }
  const archived = isArchived(repo);
  const fork = isFork(repo);
  return {
    kind: 'repository',
    externalKey: `bitbucket:${ws}/${slug}`,
    name: typeof repo.name === 'string' && repo.name.length > 0 ? repo.name : slug,
    source: 'bitbucket',
    exposure: repo.is_private ? 'internal' : 'internet_facing',
    attributes: {
      htmlUrl: bitbucketHtmlUrl(ws, slug),
      cloneUrl: bitbucketCloneUrl(ws, slug),
      bitbucketHost: 'bitbucket.org',
      defaultBranch: repo.mainbranch?.name ?? null,
      language: repo.language ?? null,
      description: repo.description ?? null,
      fork,
      archived,
      private: repo.is_private,
      pushedAt: repo.updated_on ?? null,
      visibility: repo.is_private ? 'private' : 'public',
    },
  };
}

export function isArchived(repo: BitbucketRepo): boolean {
  return repo.archived === true || repo.is_archived === true;
}

export function isFork(repo: BitbucketRepo): boolean {
  return repo.parent != null && typeof repo.parent === 'object';
}

/**
 * Repository inventory via the Bitbucket Cloud REST API
 * (`GET /2.0/repositories/{workspace}`). Same persistence path as GitHub and
 * GitLab: discover → UpsertAssetRequest → scheduler upsert + archiveStale
 * scoped per integrationId.
 *
 * Host is pinned to `api.bitbucket.org`. There is no Server / Data Center
 * `baseUrl`. Clone and html URLs are synthesized on `bitbucket.org`.
 * Credentials are platform-operated `env:BITBUCKET_*` and fail closed when
 * missing — there is no public-listing / anonymous fallback.
 *
 * Complete-signal is a missing `next`, not page length. A last page of
 * {@link BITBUCKET_PER_PAGE} with no `next` succeeds. A leftover `next` at
 * the page cap throws so archiveStale cannot run on a partial list. `next`
 * is allowlisted before any further GET and is never trusted as a host.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — the workspace
 * repository list does not offer a reliable incremental window.
 */
@Injectable()
export class BitbucketConnector implements AssetConnector {
  readonly provider = 'bitbucket';
  readonly assetKinds = ['repository'];
  private readonly log = rootLogger.child({ component: 'bitbucket-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantWritableEndpoint(ctx.config);
    const config = BitbucketConnectorConfig.parse(ctx.config);
    assertBitbucketWorkspace(config.workspace);
    const token = requireBitbucketToken(ctx.credentialRef);
    const allow = config.repos?.length ? new Set(config.repos) : null;

    let seen = 0;
    for await (const repo of this.listRepos(config.workspace, token)) {
      if (!inWorkspace(repo, config.workspace)) continue;
      const slug = requiredSlug(repo);
      assertBitbucketRepoSlug(slug);
      if (allow && !allow.has(slug)) continue;
      if (isArchived(repo) && !config.includeArchived) continue;
      if (isFork(repo) && !config.includeForks) continue;
      seen += 1;
      yield repoToAsset(repo, config.workspace);
    }
    this.log.info({ workspace: config.workspace, repos: seen }, 'bitbucket discovery complete');
  }

  /**
   * Complete-signal is missing `next`, not page length. Only a leftover
   * `next` after the cap is truncated / fail-closed.
   */
  private async *listRepos(workspace: string, token: string): AsyncIterable<BitbucketRepo> {
    let url = bitbucketRepositoriesUrl(workspace, 1, BITBUCKET_PER_PAGE);
    for (let page = 1; page <= BITBUCKET_MAX_PAGES; page++) {
      const { repos, next } = await this.getPage(url, workspace, token);
      for (const repo of repos) yield repo;
      if (!next) return;
      const nextUrl = allowlistedBitbucketApiUrl(next, workspace);
      if (page === BITBUCKET_MAX_PAGES) this.failTruncated(workspace);
      url = nextUrl;
    }
  }

  private failTruncated(workspace: string): never {
    this.log.error(
      { workspace, pages: BITBUCKET_MAX_PAGES, perPage: BITBUCKET_PER_PAGE },
      'bitbucket listing truncated at page cap',
    );
    throw new Error(
      `Bitbucket listing truncated at ${BITBUCKET_MAX_PAGES * BITBUCKET_PER_PAGE} repositories (page cap ${BITBUCKET_MAX_PAGES}); refusing to archive unseen assets`,
    );
  }

  private async getPage(
    url: string,
    workspace: string,
    token: string,
  ): Promise<{ repos: BitbucketRepo[]; next: string | undefined }> {
    const dest = allowlistedBitbucketApiUrl(url, workspace);
    const res = await inventoryEgressFetch(EGRESS_BITBUCKET_API, dest, {
      method: 'GET',
      redirect: 'error',
      headers: {
        accept: 'application/json',
        'user-agent': 'ctem-platform',
        authorization: `Bearer ${token}`,
      },
    });
    if (!res.ok) {
      throw new Error(`Bitbucket API returned ${res.status} for /2.0/repositories/${workspace}`);
    }
    let json: unknown;
    try {
      json = await res.json();
    } catch {
      throw new Error('Bitbucket repository listing was not JSON — refusing incomplete inventory');
    }
    return parsePage(json);
  }
}

function requiredSlug(repo: BitbucketRepo): string {
  if (typeof repo.slug !== 'string' || repo.slug.length === 0) {
    throw new Error('Refusing Bitbucket repository with an unusable slug — refusing incomplete inventory');
  }
  return repo.slug;
}

function inWorkspace(repo: BitbucketRepo, workspace: string): boolean {
  const want = workspace.toLowerCase();
  const slug = repo.workspace?.slug;
  if (typeof slug === 'string' && slug.length > 0 && slug.toLowerCase() !== want) return false;
  const full = repo.full_name;
  if (typeof full === 'string' && full.length > 0) {
    const owner = full.split('/')[0] ?? '';
    if (owner.toLowerCase() !== want) return false;
  }
  return true;
}

function parsePage(json: unknown): { repos: BitbucketRepo[]; next: string | undefined } {
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    throw new Error('Bitbucket repository listing was not a JSON object — refusing incomplete inventory');
  }
  const obj = json as Record<string, unknown>;
  const values = obj.values;
  if (!Array.isArray(values)) {
    throw new Error(
      'Bitbucket repository listing values was not a JSON array — refusing incomplete inventory',
    );
  }
  const repos: BitbucketRepo[] = [];
  for (const raw of values) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error(
        'Bitbucket repository listing contained a non-object — refusing incomplete inventory',
      );
    }
    repos.push(raw as BitbucketRepo);
  }
  const next = obj.next;
  if (next == null || next === '') return { repos, next: undefined };
  if (typeof next !== 'string' || next.trim() === '') {
    throw new Error('Bitbucket repository listing next was not a URL — refusing incomplete inventory');
  }
  return { repos, next: next.trim() };
}

import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { resolveCredential } from './credentials';
import {
  GITLAB_COM,
  GITLAB_COM_API_URL,
  type GitLabOrigin,
  allowlistedGitLabApiUrl,
  parseGitLabBaseUrl,
  refuseExtraGitLabHosts,
} from './gitlab.egress';

export interface GitLabProject {
  name: string;
  path: string;
  path_with_namespace: string;
  visibility: 'private' | 'internal' | 'public' | string;
  archived: boolean;
  forked_from_project?: unknown;
  web_url?: string;
  default_branch?: string;
  description?: string | null;
  last_activity_at?: string;
  namespace?: { path?: string; kind?: string; full_path?: string };
  http_url_to_repo?: string;
  ssh_url_to_repo?: string;
}

export const GitLabConnectorConfig = z.object({
  /** User or group namespace whose projects to inventory. */
  owner: z.string().min(1),
  /**
   * Required so a group integration cannot silently hit /users/:id/projects
   * (or the reverse) and yield zero — then archive inventory.
   */
  ownerType: z.enum(['user', 'group']),
  /** Optional allowlist of project paths; omit to inventory everything. */
  repos: z.array(z.string().min(1)).optional(),
  includeArchived: z.boolean().optional(),
  includeForks: z.boolean().optional(),
  /**
   * Optional self-hosted origin. Default gitlab.com. https only, no userinfo,
   * no git@. Extra host fields (host, apiUrl, hosts, …) are refused.
   */
  baseUrl: z.string().min(1).optional(),
});
export type GitLabConnectorConfig = z.infer<typeof GitLabConnectorConfig>;

/** gitlab.com default — self-hosted uses explicit connector `baseUrl`. */
export const GITLAB_API_URL = GITLAB_COM_API_URL;
export const GITLAB_PER_PAGE = 100;
export const GITLAB_MAX_PAGES = 20;

const GITLAB_SEGMENT = /^[\w.-]+$/;

/** Pure mapping from a GitLab project to our asset shape. */
export function projectToAsset(
  project: GitLabProject,
  origin: GitLabOrigin = GITLAB_COM,
): UpsertAssetRequest {
  const path = safeGitLabPath(project.path_with_namespace);
  const isPublic = project.visibility === 'public';
  return {
    kind: 'repository',
    externalKey: `gitlab:${path}`,
    name: project.path || project.name,
    source: 'gitlab',
    exposure: isPublic ? 'internet_facing' : 'internal',
    attributes: {
      // Display only — SCA refuses htmlUrl / url as clone egress.
      htmlUrl: project.web_url ?? null,
      // Synthesized from the configured origin + path_with_namespace, never
      // the API's http_url_to_repo / ssh_url_to_repo (those can point at an
      // arbitrary host).
      cloneUrl: `${origin.origin}/${path}.git`,
      gitlabHost: origin.host,
      defaultBranch: project.default_branch ?? null,
      description: project.description ?? null,
      fork: Boolean(project.forked_from_project),
      archived: project.archived,
      pushedAt: project.last_activity_at ?? null,
      visibility: project.visibility,
      // internal/private both need auth to clone; SCA fail-closed uses this.
      private: !isPublic,
    },
  };
}

export function safeGitLabPath(pathWithNamespace: string): string {
  const parts = pathWithNamespace.split('/').filter(Boolean);
  if (parts.length < 2 || parts.length > 10 || !parts.every((p) => GITLAB_SEGMENT.test(p))) {
    throw new Error(`Refusing GitLab path_with_namespace '${pathWithNamespace}'`);
  }
  return parts.join('/');
}

/**
 * Repository inventory via the GitLab REST API. Same persistence path as
 * GitHub: discover → UpsertAssetRequest → scheduler upsert + archiveStale
 * scoped per integrationId.
 *
 * Host is gitlab.com unless connector `baseUrl` names a self-hosted origin.
 * Tenant-writable extra host fields must not choose a host. Clone URLs are
 * synthesized from that origin, never from `http_url_to_repo`.
 *
 * This connector always full-scans. `ctx.orgId` is unused (tenancy is applied
 * by the scheduler on persist) and `ctx.since` is unused — GitLab's project
 * list endpoints do not offer a reliable incremental window for this inventory.
 */
@Injectable()
export class GitLabConnector implements AssetConnector {
  readonly provider = 'gitlab';
  readonly assetKinds = ['repository'];
  private readonly log = rootLogger.child({ component: 'gitlab-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseExtraGitLabHosts(ctx.config);
    const config = GitLabConnectorConfig.parse(ctx.config);
    const origin = parseGitLabBaseUrl(config.baseUrl);

    const token = resolveCredential(ctx.credentialRef);
    if (ctx.credentialRef && !token) {
      throw new Error(
        `credentialRef '${ctx.credentialRef}' is set but cannot be used — refusing to list unauthenticated ` +
          '(private GitLab projects would be missed; a public-only listing must not archive inventory)',
      );
    }
    if (!token) {
      this.log.warn(
        { integrationId: ctx.integrationId, owner: config.owner, host: origin.host },
        'no GitLab credential — only public projects will be discovered',
      );
    }
    const allow = config.repos?.length ? new Set(config.repos) : null;

    let seen = 0;
    for await (const project of this.listProjects(config, token, origin)) {
      if (allow && !allow.has(project.path) && !allow.has(project.name)) continue;
      if (project.archived && !config.includeArchived) continue;
      if (project.forked_from_project && !config.includeForks) continue;
      seen += 1;
      yield projectToAsset(project, origin);
    }
    this.log.info({ owner: config.owner, host: origin.host, projects: seen }, 'gitlab discovery complete');
  }

  private async *listProjects(
    config: GitLabConnectorConfig,
    token: string | undefined,
    origin: GitLabOrigin,
  ): AsyncIterable<GitLabProject> {
    const owner = encodeURIComponent(config.owner);
    const path =
      config.ownerType === 'group'
        ? `/groups/${owner}/projects?include_subgroups=true`
        : token
          ? // Authenticated owned listing includes private projects. GET
            // /users/:id/projects can 200 with [] for a private profile and
            // would archive live inventory. Filtered to the owner below.
            `/projects?owned=true`
          : `/users/${owner}/projects`;

    for (let page = 1; page <= GITLAB_MAX_PAGES; page++) {
      const sep = path.includes('?') ? '&' : '?';
      const url = allowlistedGitLabApiUrl(
        `${origin.apiUrl}${path}${sep}per_page=${GITLAB_PER_PAGE}&page=${page}`,
        origin,
      );
      const res = await fetch(url, {
        headers: {
          accept: 'application/json',
          'user-agent': 'ctem-platform',
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        signal: AbortSignal.timeout(20_000),
      });
      if (!res.ok) {
        throw new Error(`GitLab API returned ${res.status} for ${path} (page ${page})`);
      }

      const projects = (await res.json()) as GitLabProject[];
      for (const project of projects) {
        if (!ownedBy(project, config.owner)) continue;
        yield project;
      }
      if (projects.length < GITLAB_PER_PAGE) break;
      if (page === GITLAB_MAX_PAGES) {
        this.log.error(
          { owner: config.owner, host: origin.host, pages: GITLAB_MAX_PAGES, perPage: GITLAB_PER_PAGE },
          'gitlab listing truncated at page cap',
        );
        throw new Error(
          `GitLab listing truncated at ${GITLAB_MAX_PAGES * GITLAB_PER_PAGE} projects (page cap ${GITLAB_MAX_PAGES}); refusing to archive unseen assets`,
        );
      }
    }
  }
}

function ownedBy(project: GitLabProject, owner: string): boolean {
  const ns = (project.path_with_namespace ?? '').toLowerCase();
  const want = owner.toLowerCase();
  return ns === want || ns.startsWith(`${want}/`);
}

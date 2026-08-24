import { Injectable } from '@nestjs/common';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { resolveCredential } from './credentials';

export interface GitHubRepo {
  name: string;
  full_name: string;
  private: boolean;
  archived: boolean;
  fork: boolean;
  html_url: string;
  default_branch?: string;
  language?: string | null;
  pushed_at?: string;
  description?: string | null;
  owner?: { login?: string };
}

export interface GitHubConnectorConfig {
  /** User or organization whose repositories to inventory. */
  owner: string;
  ownerType?: 'user' | 'org';
  /** Optional allowlist of repo names; omit to inventory everything. */
  repos?: string[];
  includeArchived?: boolean;
  includeForks?: boolean;
}

/** Pure mapping from a GitHub repository to our asset shape. */
export function repoToAsset(repo: GitHubRepo): UpsertAssetRequest {
  return {
    kind: 'repository',
    externalKey: `github:${repo.full_name}`,
    name: repo.name,
    source: 'github',
    // A public repo's code is exposed to the internet by definition; a private
    // one is internal until business context says otherwise.
    exposure: repo.private ? 'internal' : 'internet_facing',
    attributes: {
      htmlUrl: repo.html_url,
      defaultBranch: repo.default_branch ?? null,
      language: repo.language ?? null,
      description: repo.description ?? null,
      fork: repo.fork,
      archived: repo.archived,
      pushedAt: repo.pushed_at ?? null,
    },
  };
}

const PER_PAGE = 100;
const MAX_PAGES = 20;

/**
 * Repository inventory via the GitHub REST API. With a token whose subject is
 * the configured user, private repositories are included (`/user/repos`);
 * without one, only the public surface is visible — which is itself useful
 * signal for an external-attack-surface view.
 */
@Injectable()
export class GitHubConnector implements AssetConnector {
  readonly provider = 'github';
  readonly assetKinds = ['repository'];
  private readonly log = rootLogger.child({ component: 'github-connector' });

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    const config = ctx.config as unknown as GitHubConnectorConfig;
    if (!config.owner) throw new Error('github connector requires config.owner');

    const token = resolveCredential(ctx.credentialRef);
    if (!token) {
      this.log.warn(
        { integrationId: ctx.integrationId, owner: config.owner },
        'no GitHub credential — only public repositories will be discovered',
      );
    }
    const allow = config.repos?.length ? new Set(config.repos) : null;

    let seen = 0;
    for await (const repo of this.listRepos(config, token)) {
      if (allow && !allow.has(repo.name)) continue;
      if (repo.archived && !config.includeArchived) continue;
      if (repo.fork && !config.includeForks) continue;
      seen += 1;
      yield repoToAsset(repo);
    }
    this.log.info({ owner: config.owner, repos: seen }, 'github discovery complete');
  }

  private async *listRepos(
    config: GitHubConnectorConfig,
    token: string | undefined,
  ): AsyncIterable<GitHubRepo> {
    const base = loadEnv().GITHUB_API_URL;
    const path =
      config.ownerType === 'org'
        ? `/orgs/${config.owner}/repos?type=all`
        : token
          ? // The authenticated-user listing is the only one that includes
            // private repos for a user account; filtered to the owner below.
            `/user/repos?affiliation=owner`
          : `/users/${config.owner}/repos`;

    for (let page = 1; page <= MAX_PAGES; page++) {
      const sep = path.includes('?') ? '&' : '?';
      const res = await fetch(`${base}${path}${sep}per_page=${PER_PAGE}&page=${page}`, {
        headers: {
          accept: 'application/vnd.github+json',
          'x-github-api-version': '2022-11-28',
          'user-agent': 'ctem-platform',
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        signal: AbortSignal.timeout(20_000),
      });
      if (!res.ok) {
        throw new Error(`GitHub API returned ${res.status} for ${path} (page ${page})`);
      }

      const repos = (await res.json()) as GitHubRepo[];
      for (const repo of repos) {
        const login = repo.owner?.login;
        if (login && login.toLowerCase() !== config.owner.toLowerCase()) continue;
        yield repo;
      }
      if (repos.length < PER_PAGE) break;
    }
  }
}

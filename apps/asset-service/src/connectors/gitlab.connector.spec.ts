import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  GitLabConnector,
  GITLAB_API_URL,
  GITLAB_MAX_PAGES,
  GITLAB_PER_PAGE,
  projectToAsset,
  safeGitLabPath,
  type GitLabProject,
} from './gitlab.connector';
import type { DiscoveryContext } from './connector.registry';

const project = (over: Partial<GitLabProject> = {}): GitLabProject => ({
  name: 'ctem-scan-target',
  path: 'ctem-scan-target',
  path_with_namespace: 'langell/ctem-scan-target',
  visibility: 'private',
  archived: false,
  web_url: 'https://gitlab.com/langell/ctem-scan-target',
  default_branch: 'main',
  description: 'fixture',
  last_activity_at: '2026-01-01T00:00:00.000Z',
  namespace: { path: 'langell', kind: 'user', full_path: 'langell' },
  ...over,
});

const ctx = (
  config: Record<string, unknown>,
  credentialRef: string | null = null,
): DiscoveryContext => ({
  orgId: 'org-1',
  integrationId: 'int-1',
  config,
  credentialRef,
  since: null,
});

const userCfg = (over: Record<string, unknown> = {}) => ({
  owner: 'langell',
  ownerType: 'user' as const,
  ...over,
});

async function collect(iter: AsyncIterable<unknown>): Promise<unknown[]> {
  const out: unknown[] = [];
  for await (const item of iter) out.push(item);
  return out;
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.GITLAB_TEST_TOKEN;
});

function stubPages(pages: GitLabProject[][]): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async (url: string | URL) => {
    const page = Number(new URL(String(url)).searchParams.get('page') ?? '1');
    return new Response(JSON.stringify(pages[page - 1] ?? []), { status: 200 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

describe('projectToAsset', () => {
  it('maps identity, exposure, synthesized cloneUrl and attributes', () => {
    expect(projectToAsset(project())).toMatchObject({
      kind: 'repository',
      externalKey: 'gitlab:langell/ctem-scan-target',
      name: 'ctem-scan-target',
      source: 'gitlab',
      exposure: 'internal',
      attributes: {
        defaultBranch: 'main',
        archived: false,
        cloneUrl: 'https://gitlab.com/langell/ctem-scan-target.git',
        gitlabHost: 'gitlab.com',
        private: true,
        visibility: 'private',
      },
    });
    expect(projectToAsset(project({ visibility: 'public' })).exposure).toBe('internet_facing');
    expect(projectToAsset(project({ visibility: 'internal' })).attributes).toMatchObject({
      private: true,
    });
  });

  it('synthesizes cloneUrl from path_with_namespace, not a foreign http_url_to_repo', () => {
    const asset = projectToAsset(
      project({
        path_with_namespace: 'acme/platform/api',
        web_url: 'https://evil.example/acme/platform/api',
        http_url_to_repo: 'https://evil.example/acme/platform/api.git',
        ssh_url_to_repo: 'git@evil.example:acme/platform/api.git',
      }),
    );
    expect(asset.externalKey).toBe('gitlab:acme/platform/api');
    expect(asset.attributes?.cloneUrl).toBe('https://gitlab.com/acme/platform/api.git');
    expect(asset.attributes?.gitlabHost).toBe('gitlab.com');
    expect(String(asset.attributes?.cloneUrl)).not.toContain('evil.example');
  });

  it('synthesizes cloneUrl from the configured baseUrl host, not http_url_to_repo', () => {
    const origin = {
      host: 'gitlab.example.com',
      origin: 'https://gitlab.example.com',
      apiUrl: 'https://gitlab.example.com/api/v4',
    };
    const asset = projectToAsset(
      project({
        path_with_namespace: 'acme/platform/api',
        web_url: 'https://evil.example/acme/platform/api',
        http_url_to_repo: 'https://evil.example/acme/platform/api.git',
      }),
      origin,
    );
    expect(asset.attributes?.cloneUrl).toBe('https://gitlab.example.com/acme/platform/api.git');
    expect(asset.attributes?.gitlabHost).toBe('gitlab.example.com');
    expect(String(asset.attributes?.cloneUrl)).not.toContain('evil.example');
    expect(String(asset.attributes?.cloneUrl)).not.toContain('gitlab.com/');
  });
});

describe('safeGitLabPath', () => {
  it('accepts nested groups and refuses malformed paths', () => {
    expect(safeGitLabPath('acme/platform/api')).toBe('acme/platform/api');
    expect(() => safeGitLabPath('only-one')).toThrow(/path_with_namespace/);
    expect(() => safeGitLabPath('acme/has space/api')).toThrow(/path_with_namespace/);
  });
});

describe('GitLabConnector.discover', () => {
  it('lists user projects with a resolved credential', async () => {
    process.env.GITLAB_TEST_TOKEN = 'glpat-token';
    const fetchFn = stubPages([
      [
        project(),
        project({
          name: 'other',
          path: 'other',
          path_with_namespace: 'someoneelse/other',
          namespace: { path: 'someoneelse', full_path: 'someoneelse' },
        }),
      ],
    ]);

    const assets = await collect(
      new GitLabConnector().discover(ctx(userCfg(), 'env:GITLAB_TEST_TOKEN')),
    );
    expect(assets).toHaveLength(1);
    const url = String(fetchFn.mock.calls[0][0]);
    expect(url).toBe(`${GITLAB_API_URL}/projects?owned=true&per_page=${GITLAB_PER_PAGE}&page=1`);
    expect(url).not.toContain('/users/');
    expect((fetchFn.mock.calls[0][1] as RequestInit).headers).toMatchObject({
      authorization: 'Bearer glpat-token',
    });
  });

  it('does not hit /users/:id/projects when a credential is present (private profiles 200 empty)', async () => {
    process.env.GITLAB_TEST_TOKEN = 'glpat-token';
    const fetchFn = stubPages([[]]);
    await collect(new GitLabConnector().discover(ctx(userCfg(), 'env:GITLAB_TEST_TOKEN')));
    const url = String(fetchFn.mock.calls[0][0]);
    expect(url).toContain('/projects?owned=true');
    expect(url).not.toContain('/users/langell/projects');
  });

  it('falls back to the public listing without a credential', async () => {
    const fetchFn = stubPages([[project({ visibility: 'public' })]]);
    const assets = await collect(new GitLabConnector().discover(ctx(userCfg())));
    expect(assets).toHaveLength(1);
    expect(String(fetchFn.mock.calls[0][0])).toContain('/users/langell/projects');
    expect((fetchFn.mock.calls[0][1] as RequestInit).headers).not.toHaveProperty('authorization');
  });

  it('defaults API and clone to gitlab.com when baseUrl is omitted', async () => {
    const fetchFn = stubPages([[project()]]);
    const assets = (await collect(new GitLabConnector().discover(ctx(userCfg())))) as Array<{
      attributes?: { cloneUrl?: string; gitlabHost?: string };
    }>;
    expect(String(fetchFn.mock.calls[0][0]).startsWith('https://gitlab.com/api/v4/')).toBe(true);
    expect(assets[0]?.attributes?.cloneUrl).toBe('https://gitlab.com/langell/ctem-scan-target.git');
    expect(assets[0]?.attributes?.gitlabHost).toBe('gitlab.com');
  });

  it('lists and clones only the configured baseUrl host, not http_url_to_repo', async () => {
    const fetchFn = stubPages([
      [
        project({
          web_url: 'https://evil.example/langell/ctem-scan-target',
          http_url_to_repo: 'https://evil.example/langell/ctem-scan-target.git',
          ssh_url_to_repo: 'git@evil.example:langell/ctem-scan-target.git',
        }),
      ],
    ]);
    const assets = (await collect(
      new GitLabConnector().discover(
        ctx(userCfg({ baseUrl: 'https://gitlab.example.com' })),
      ),
    )) as Array<{ attributes?: { cloneUrl?: string; gitlabHost?: string } }>;
    const url = String(fetchFn.mock.calls[0][0]);
    expect(url.startsWith('https://gitlab.example.com/api/v4/')).toBe(true);
    expect(url).toContain('/users/langell/projects');
    expect(url).not.toContain('evil.example');
    expect(url).not.toContain('gitlab.com/');
    expect(assets[0]?.attributes?.cloneUrl).toBe(
      'https://gitlab.example.com/langell/ctem-scan-target.git',
    );
    expect(assets[0]?.attributes?.gitlabHost).toBe('gitlab.example.com');
  });

  it('is https-only for baseUrl', async () => {
    const fetchFn = stubPages([[]]);
    await expect(
      collect(new GitLabConnector().discover(ctx(userCfg({ baseUrl: 'http://gitlab.example.com' })))),
    ).rejects.toThrow(/non-https/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects userinfo and git@ in baseUrl', async () => {
    const fetchFn = stubPages([[]]);
    await expect(
      collect(
        new GitLabConnector().discover(
          ctx(userCfg({ baseUrl: 'https://user:pass@gitlab.example.com' })),
        ),
      ),
    ).rejects.toThrow(/userinfo/);
    await expect(
      collect(
        new GitLabConnector().discover(ctx(userCfg({ baseUrl: 'git@gitlab.example.com:acme/api.git' }))),
      ),
    ).rejects.toThrow(/git@/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses extra tenant-writable hosts — only connector baseUrl may set the host', async () => {
    const fetchFn = stubPages([[]]);
    await expect(
      collect(
        new GitLabConnector().discover(
          ctx({
            owner: 'langell',
            ownerType: 'user',
            host: 'evil.example',
            apiUrl: 'https://evil.example/api/v4',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable GitLab host/);
    await expect(
      collect(
        new GitLabConnector().discover(
          ctx(userCfg({ baseUrl: 'https://gitlab.example.com', hosts: ['evil.example'] })),
        ),
      ),
    ).rejects.toThrow(/tenant-writable GitLab host/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('still uses the authenticated owned listing on a self-hosted host when a credential is present', async () => {
    process.env.GITLAB_TEST_TOKEN = 'glpat-token';
    const fetchFn = stubPages([[]]);
    await collect(
      new GitLabConnector().discover(
        ctx(userCfg({ baseUrl: 'https://gitlab.example.com' }), 'env:GITLAB_TEST_TOKEN'),
      ),
    );
    const url = String(fetchFn.mock.calls[0][0]);
    expect(url).toBe(
      `https://gitlab.example.com/api/v4/projects?owned=true&per_page=${GITLAB_PER_PAGE}&page=1`,
    );
    expect(url).not.toContain('/users/');
  });

  it('lists group projects (including subgroups) when ownerType is group', async () => {
    const fetchFn = stubPages([
      [
        project({
          name: 'org-repo',
          path: 'org-repo',
          path_with_namespace: 'acme/org-repo',
          namespace: { path: 'acme', kind: 'group', full_path: 'acme' },
        }),
      ],
    ]);
    const assets = await collect(
      new GitLabConnector().discover(ctx({ owner: 'acme', ownerType: 'group' })),
    );
    expect(assets).toHaveLength(1);
    expect(String(fetchFn.mock.calls[0][0])).toContain('/groups/acme/projects');
    expect(String(fetchFn.mock.calls[0][0])).toContain('include_subgroups=true');
  });

  it('encodes owner in the listing path', async () => {
    const fetchFn = stubPages([[]]);
    await collect(
      new GitLabConnector().discover(ctx({ owner: 'acme?evil=1', ownerType: 'user' })),
    );
    const url = String(fetchFn.mock.calls[0][0]);
    expect(url).toContain('/users/acme%3Fevil%3D1/projects');
    expect(url).not.toContain('/users/acme?evil=1');
  });

  it('encodes a nested group path as a single id segment', async () => {
    const fetchFn = stubPages([[]]);
    await collect(
      new GitLabConnector().discover(ctx({ owner: 'acme/platform', ownerType: 'group' })),
    );
    const url = String(fetchFn.mock.calls[0][0]);
    expect(url).toContain('/groups/acme%2Fplatform/projects');
  });

  it('requires ownerType so a group integration cannot silently list /users/:id/projects', async () => {
    await expect(
      collect(new GitLabConnector().discover(ctx({ owner: 'langell' }))),
    ).rejects.toThrow(/ownerType/);
  });

  it('rejects ownerType org — GitLab uses group, not GitHub org', async () => {
    await expect(
      collect(new GitLabConnector().discover(ctx({ owner: 'acme', ownerType: 'org' }))),
    ).rejects.toThrow(/ownerType/);
  });

  it('rejects a string repos allowlist and a string includeArchived', async () => {
    await expect(
      collect(new GitLabConnector().discover(ctx(userCfg({ repos: 'ctem-scan-target' })))),
    ).rejects.toThrow();
    await expect(
      collect(new GitLabConnector().discover(ctx(userCfg({ includeArchived: 'false' })))),
    ).rejects.toThrow();
  });

  it('honors the repos allowlist and skips archived and forked projects', async () => {
    stubPages([
      [
        project(),
        project({ name: 'not-allowed', path: 'not-allowed', path_with_namespace: 'langell/not-allowed' }),
        project({ path: 'ctem-scan-target', archived: true }),
        project({
          name: 'a-fork',
          path: 'a-fork',
          path_with_namespace: 'langell/a-fork',
          forked_from_project: { id: 1 },
        }),
      ],
    ]);
    const assets = (await collect(
      new GitLabConnector().discover(ctx(userCfg({ repos: ['ctem-scan-target'] }))),
    )) as Array<{ name: string }>;
    expect(assets.map((a) => a.name)).toEqual(['ctem-scan-target']);
  });

  it('walks pagination until a short page', async () => {
    const pageOne = Array.from({ length: GITLAB_PER_PAGE }, (_, i) =>
      project({ path: `repo-${i}`, name: `repo-${i}`, path_with_namespace: `langell/repo-${i}` }),
    );
    const fetchFn = stubPages([
      pageOne,
      [project({ path: 'last', name: 'last', path_with_namespace: 'langell/last' })],
    ]);
    const assets = await collect(new GitLabConnector().discover(ctx(userCfg())));
    expect(assets).toHaveLength(GITLAB_PER_PAGE + 1);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('fails when the listing is truncated at the page cap', async () => {
    const pages = Array.from({ length: GITLAB_MAX_PAGES }, (_, p) =>
      Array.from({ length: GITLAB_PER_PAGE }, (_, i) =>
        project({ path: `r-${p}-${i}`, name: `r-${p}-${i}`, path_with_namespace: `langell/r-${p}-${i}` }),
      ),
    );
    const fetchFn = stubPages(pages);
    await expect(collect(new GitLabConnector().discover(ctx(userCfg())))).rejects.toThrow(/truncated/);
    expect(fetchFn).toHaveBeenCalledTimes(GITLAB_MAX_PAGES);
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('rate limited', { status: 403 })));
    await expect(collect(new GitLabConnector().discover(ctx(userCfg())))).rejects.toThrow(/403/);
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(collect(new GitLabConnector().discover(ctx(userCfg(), 'vault:gl')))).rejects.toThrow(
      /Unsupported credentialRef scheme/,
    );
  });

  it('fails closed when credentialRef is set but the env var is empty', async () => {
    await expect(
      collect(new GitLabConnector().discover(ctx(userCfg(), 'env:GITLAB_TEST_TOKEN'))),
    ).rejects.toThrow(/cannot be used/);
    await expect(
      collect(
        new GitLabConnector().discover(
          ctx(userCfg({ baseUrl: 'https://gitlab.example.com' }), 'env:GITLAB_TEST_TOKEN'),
        ),
      ),
    ).rejects.toThrow(/cannot be used/);
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret', async () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    await expect(
      collect(new GitLabConnector().discover(ctx(userCfg(), 'env:DATABASE_URL'))),
    ).rejects.toThrow(/not allowlisted/);
  });
});

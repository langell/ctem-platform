import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  GitHubConnector,
  GITHUB_MAX_PAGES,
  GITHUB_PER_PAGE,
  repoToAsset,
  type GitHubRepo,
} from './github.connector';
import type { DiscoveryContext } from './connector.registry';

const repo = (over: Partial<GitHubRepo> = {}): GitHubRepo => ({
  name: 'ctem-scan-target',
  full_name: 'langell/ctem-scan-target',
  private: true,
  archived: false,
  fork: false,
  html_url: 'https://github.com/langell/ctem-scan-target',
  default_branch: 'main',
  language: 'JavaScript',
  owner: { login: 'langell' },
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
  delete process.env.GITHUB_TEST_TOKEN;
});

function stubPages(pages: GitHubRepo[][]): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async (url: string | URL) => {
    const page = Number(new URL(String(url)).searchParams.get('page') ?? '1');
    return new Response(JSON.stringify(pages[page - 1] ?? []), { status: 200 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

describe('repoToAsset', () => {
  it('maps identity, exposure and attributes', () => {
    expect(repoToAsset(repo())).toMatchObject({
      kind: 'repository',
      externalKey: 'github:langell/ctem-scan-target',
      name: 'ctem-scan-target',
      source: 'github',
      exposure: 'internal',
      attributes: { defaultBranch: 'main', language: 'JavaScript', archived: false, private: true },
    });
    expect(repoToAsset(repo({ private: false })).exposure).toBe('internet_facing');
  });
});

describe('GitHubConnector.discover', () => {
  it('uses the authenticated listing when a credential resolves, filtered to the owner', async () => {
    process.env.GITHUB_TEST_TOKEN = 'gh-token';
    const fetchFn = stubPages([
      [repo(), repo({ name: 'other', full_name: 'someoneelse/other', owner: { login: 'someoneelse' } })],
    ]);

    const assets = await collect(
      new GitHubConnector().discover(ctx(userCfg(), 'env:GITHUB_TEST_TOKEN')),
    );
    expect(assets).toHaveLength(1);
    expect(String(fetchFn.mock.calls[0][0])).toContain('/user/repos');
    expect((fetchFn.mock.calls[0][1] as RequestInit).headers).toMatchObject({
      authorization: 'Bearer gh-token',
    });
  });

  it('falls back to the public listing without a credential', async () => {
    const fetchFn = stubPages([[repo({ private: false })]]);
    const assets = await collect(new GitHubConnector().discover(ctx(userCfg())));
    expect(assets).toHaveLength(1);
    expect(String(fetchFn.mock.calls[0][0])).toContain('/users/langell/repos');
  });

  it('lists organization repositories when ownerType is org', async () => {
    const fetchFn = stubPages([
      [repo({ name: 'org-repo', full_name: 'acme/org-repo', owner: { login: 'acme' } })],
    ]);
    const assets = await collect(
      new GitHubConnector().discover(ctx({ owner: 'acme', ownerType: 'org' })),
    );
    expect(assets).toHaveLength(1);
    expect(String(fetchFn.mock.calls[0][0])).toContain('/orgs/acme/repos');
  });

  it('encodes owner in the listing path', async () => {
    const fetchFn = stubPages([[]]);
    await collect(
      new GitHubConnector().discover(ctx({ owner: 'acme?evil=1', ownerType: 'user' })),
    );
    const url = String(fetchFn.mock.calls[0][0]);
    expect(url).toContain('/users/acme%3Fevil%3D1/repos');
    expect(url).not.toContain('/users/acme?evil=1');
  });

  it('requires ownerType so an org integration cannot silently list /user/repos', async () => {
    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell' }))),
    ).rejects.toThrow(/ownerType/);
  });

  it('rejects a string repos allowlist and a string includeArchived', async () => {
    await expect(
      collect(new GitHubConnector().discover(ctx(userCfg({ repos: 'ctem-scan-target' })))),
    ).rejects.toThrow();
    await expect(
      collect(new GitHubConnector().discover(ctx(userCfg({ includeArchived: 'false' })))),
    ).rejects.toThrow();
  });

  it('honors the repos allowlist and skips archived and forked repos', async () => {
    stubPages([
      [
        repo(),
        repo({ name: 'not-allowed', full_name: 'langell/not-allowed' }),
        repo({ name: 'ctem-scan-target', archived: true }),
        repo({ name: 'a-fork', full_name: 'langell/a-fork', fork: true }),
      ],
    ]);
    const assets = (await collect(
      new GitHubConnector().discover(ctx(userCfg({ repos: ['ctem-scan-target'] }))),
    )) as Array<{ name: string }>;
    expect(assets.map((a) => a.name)).toEqual(['ctem-scan-target']);
  });

  it('walks pagination until a short page', async () => {
    const pageOne = Array.from({ length: GITHUB_PER_PAGE }, (_, i) =>
      repo({ name: `repo-${i}`, full_name: `langell/repo-${i}` }),
    );
    const fetchFn = stubPages([pageOne, [repo({ name: 'last', full_name: 'langell/last' })]]);
    const assets = await collect(new GitHubConnector().discover(ctx(userCfg())));
    expect(assets).toHaveLength(GITHUB_PER_PAGE + 1);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('fails when the listing is truncated at the page cap', async () => {
    const pages = Array.from({ length: GITHUB_MAX_PAGES }, (_, p) =>
      Array.from({ length: GITHUB_PER_PAGE }, (_, i) =>
        repo({ name: `r-${p}-${i}`, full_name: `langell/r-${p}-${i}` }),
      ),
    );
    const fetchFn = stubPages(pages);
    await expect(collect(new GitHubConnector().discover(ctx(userCfg())))).rejects.toThrow(
      /truncated/,
    );
    expect(fetchFn).toHaveBeenCalledTimes(GITHUB_MAX_PAGES);
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('rate limited', { status: 403 })));
    await expect(collect(new GitHubConnector().discover(ctx(userCfg())))).rejects.toThrow(/403/);
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(
      collect(new GitHubConnector().discover(ctx(userCfg(), 'vault:gh'))),
    ).rejects.toThrow(/Unsupported credentialRef scheme/);
  });
});

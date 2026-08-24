import { afterEach, describe, expect, it, vi } from 'vitest';
import { GitHubConnector, repoToAsset, type GitHubRepo } from './github.connector';
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

async function collect(iter: AsyncIterable<unknown>): Promise<unknown[]> {
  const out: unknown[] = [];
  for await (const item of iter) out.push(item);
  return out;
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.TEST_GH_TOKEN;
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
      attributes: { defaultBranch: 'main', language: 'JavaScript', archived: false },
    });
    expect(repoToAsset(repo({ private: false })).exposure).toBe('internet_facing');
  });
});

describe('GitHubConnector.discover', () => {
  it('uses the authenticated listing when a credential resolves, filtered to the owner', async () => {
    process.env.TEST_GH_TOKEN = 'gh-token';
    const fetchFn = stubPages([[repo(), repo({ name: 'other', full_name: 'someoneelse/other', owner: { login: 'someoneelse' } })]]);

    const assets = await collect(
      new GitHubConnector().discover(ctx({ owner: 'langell' }, 'env:TEST_GH_TOKEN')),
    );
    expect(assets).toHaveLength(1);
    expect(String(fetchFn.mock.calls[0][0])).toContain('/user/repos');
    expect((fetchFn.mock.calls[0][1] as RequestInit).headers).toMatchObject({
      authorization: 'Bearer gh-token',
    });
  });

  it('falls back to the public listing without a credential', async () => {
    const fetchFn = stubPages([[repo({ private: false })]]);
    const assets = await collect(new GitHubConnector().discover(ctx({ owner: 'langell' })));
    expect(assets).toHaveLength(1);
    expect(String(fetchFn.mock.calls[0][0])).toContain('/users/langell/repos');
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
      new GitHubConnector().discover(ctx({ owner: 'langell', repos: ['ctem-scan-target'] })),
    )) as Array<{ name: string }>;
    expect(assets.map((a) => a.name)).toEqual(['ctem-scan-target']);
  });

  it('walks pagination until a short page', async () => {
    const pageOne = Array.from({ length: 100 }, (_, i) =>
      repo({ name: `repo-${i}`, full_name: `langell/repo-${i}` }),
    );
    const fetchFn = stubPages([pageOne, [repo({ name: 'last', full_name: 'langell/last' })]]);
    const assets = await collect(new GitHubConnector().discover(ctx({ owner: 'langell' })));
    expect(assets).toHaveLength(101);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('rate limited', { status: 403 })));
    await expect(collect(new GitHubConnector().discover(ctx({ owner: 'langell' })))).rejects.toThrow(
      /403/,
    );
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell' }, 'vault:gh'))),
    ).rejects.toThrow(/Unsupported credentialRef scheme/);
  });
});

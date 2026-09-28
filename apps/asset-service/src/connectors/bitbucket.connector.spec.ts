import { afterEach, describe, expect, it, vi } from 'vitest';
import { PrismaService } from '@ctem/db';
import {
  CircuitOpenError,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  InternalHttpPolicy,
} from '@ctem/resilience';
import {
  BITBUCKET_MAX_PAGES,
  BITBUCKET_PER_PAGE,
  BitbucketConnector,
  repoToAsset,
  type BitbucketRepo,
} from './bitbucket.connector';
import { ConnectorRegistry, type DiscoveryContext } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';
import { EGRESS_BITBUCKET_API, resetInventoryEgressPolicy, useInventoryEgressPolicy } from './inventory-egress';

const repo = (over: Partial<BitbucketRepo> = {}): BitbucketRepo => ({
  name: 'ctem-scan-target',
  slug: 'ctem-scan-target',
  full_name: 'langell/ctem-scan-target',
  is_private: true,
  description: 'fixture',
  language: 'TypeScript',
  updated_on: '2026-01-01T00:00:00.000Z',
  mainbranch: { name: 'main' },
  workspace: { slug: 'langell' },
  ...over,
});

const ctx = (
  config: Record<string, unknown>,
  credentialRef: string | null = 'env:BITBUCKET_TOKEN',
): DiscoveryContext => ({
  orgId: 'org-1',
  integrationId: 'int-1',
  config,
  credentialRef,
  since: null,
});

const cfg = (over: Record<string, unknown> = {}) => ({
  workspace: 'langell',
  ...over,
});

function page(values: BitbucketRepo[], next?: string): unknown {
  return next ? { values, next } : { values };
}

async function collect(iter: AsyncIterable<unknown>): Promise<unknown[]> {
  const out: unknown[] = [];
  for await (const item of iter) out.push(item);
  return out;
}

function setToken(value = 'bb-token'): void {
  process.env.BITBUCKET_TOKEN = value;
}

afterEach(() => {
  resetInventoryEgressPolicy();
  vi.unstubAllGlobals();
  delete process.env.BITBUCKET_TOKEN;
  delete process.env.BITBUCKET_TEST_TOKEN;
  delete process.env.GITHUB_TOKEN;
  delete process.env.DATABASE_URL;
});

describe('repoToAsset', () => {
  it('maps identity, exposure, and attributes', () => {
    expect(repoToAsset(repo(), 'langell')).toMatchObject({
      kind: 'repository',
      externalKey: 'bitbucket:langell/ctem-scan-target',
      name: 'ctem-scan-target',
      source: 'bitbucket',
      exposure: 'internal',
      attributes: {
        htmlUrl: 'https://bitbucket.org/langell/ctem-scan-target',
        cloneUrl: 'https://bitbucket.org/langell/ctem-scan-target.git',
        bitbucketHost: 'bitbucket.org',
        defaultBranch: 'main',
        language: 'TypeScript',
        archived: false,
        fork: false,
        private: true,
        visibility: 'private',
      },
    });
    expect(repoToAsset(repo({ is_private: false }), 'langell').exposure).toBe('internet_facing');
  });

  it('synthesizes cloneUrl and htmlUrl from bitbucket.org, not API links', () => {
    const asset = repoToAsset(
      repo({
        links: {
          html: { href: 'https://evil.example/langell/ctem-scan-target' },
          clone: [
            { name: 'https', href: 'https://evil.example/langell/ctem-scan-target.git' },
            { name: 'ssh', href: 'git@evil.example:langell/ctem-scan-target.git' },
          ],
        },
      }),
      'langell',
    );
    expect(asset.externalKey).toBe('bitbucket:langell/ctem-scan-target');
    expect(asset.attributes?.cloneUrl).toBe('https://bitbucket.org/langell/ctem-scan-target.git');
    expect(asset.attributes?.htmlUrl).toBe('https://bitbucket.org/langell/ctem-scan-target');
    expect(JSON.stringify(asset)).not.toContain('evil.example');
    expect(String(asset.attributes?.cloneUrl)).not.toContain('api.bitbucket.org');
  });

  it('refuses a repository without is_private', () => {
    expect(() => repoToAsset(repo({ is_private: undefined }), 'langell')).toThrow(/is_private/);
  });
});

describe('BitbucketConnector.discover', () => {
  it('lists the workspace with a bearer token on the pinned Cloud host', async () => {
    setToken();
    const fetchFn = vi.fn(async () => new Response(JSON.stringify(page([repo()])), { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);

    const assets = await collect(new BitbucketConnector().discover(ctx(cfg())));
    expect(assets).toHaveLength(1);
    expect(assets[0]).toMatchObject({ externalKey: 'bitbucket:langell/ctem-scan-target', source: 'bitbucket' });
    const url = String(fetchFn.mock.calls[0]![0]);
    expect(url).toBe(
      `https://api.bitbucket.org/2.0/repositories/langell?pagelen=${BITBUCKET_PER_PAGE}&page=1`,
    );
    expect(new URL(url).hostname).toBe('api.bitbucket.org');
    expect(fetchFn.mock.calls[0]![1]).toMatchObject({
      redirect: 'error',
      headers: { authorization: 'Bearer bb-token' },
    });
  });

  it('honors the repo-slug allowlist and skips archived repos and forks', async () => {
    setToken();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify(
            page([
              repo(),
              repo({ name: 'Not allowed', slug: 'not-allowed', full_name: 'langell/not-allowed' }),
              repo({ slug: 'old', name: 'old', full_name: 'langell/old', archived: true }),
              repo({
                slug: 'a-fork',
                name: 'a-fork',
                full_name: 'langell/a-fork',
                parent: { full_name: 'other/a-fork' },
              }),
            ]),
          ),
          { status: 200 },
        ),
      ),
    );
    const assets = (await collect(
      new BitbucketConnector().discover(ctx(cfg({ repos: ['ctem-scan-target'] }))),
    )) as Array<{ name: string }>;
    expect(assets.map((a) => a.name)).toEqual(['ctem-scan-target']);
  });

  it('includes archived repos and forks when asked', async () => {
    setToken();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify(
            page([
              repo({ slug: 'old', name: 'old', full_name: 'langell/old', is_archived: true }),
              repo({
                slug: 'a-fork',
                name: 'a-fork',
                full_name: 'langell/a-fork',
                parent: { full_name: 'other/a-fork' },
              }),
            ]),
          ),
          { status: 200 },
        ),
      ),
    );
    const assets = (await collect(
      new BitbucketConnector().discover(ctx(cfg({ includeArchived: true, includeForks: true }))),
    )) as Array<{ externalKey: string }>;
    expect(assets.map((a) => a.externalKey)).toEqual(['bitbucket:langell/old', 'bitbucket:langell/a-fork']);
  });

  it('skips repositories that belong to another workspace', async () => {
    setToken();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify(
            page([
              repo(),
              repo({
                slug: 'secret',
                name: 'secret',
                full_name: 'someoneelse/secret',
                workspace: { slug: 'someoneelse' },
              }),
            ]),
          ),
          { status: 200 },
        ),
      ),
    );
    const assets = (await collect(new BitbucketConnector().discover(ctx(cfg())))) as Array<{
      externalKey: string;
    }>;
    expect(assets.map((a) => a.externalKey)).toEqual(['bitbucket:langell/ctem-scan-target']);
  });

  it('follows an allowlisted next and stops when next is absent, even on a full page', async () => {
    setToken();
    const full = Array.from({ length: BITBUCKET_PER_PAGE }, (_, i) =>
      repo({ slug: `repo-${i}`, name: `repo-${i}`, full_name: `langell/repo-${i}` }),
    );
    const fetchFn = vi.fn(async (url: string) => {
      const pageNo = new URL(String(url)).searchParams.get('page');
      if (pageNo === '1') {
        return new Response(
          JSON.stringify(
            page(full, 'https://api.bitbucket.org/2.0/repositories/langell?pagelen=100&page=2'),
          ),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify(page([repo({ slug: 'last', name: 'last', full_name: 'langell/last' })])),
        { status: 200 },
      );
    });
    vi.stubGlobal('fetch', fetchFn);
    const assets = await collect(new BitbucketConnector().discover(ctx(cfg())));
    expect(assets).toHaveLength(BITBUCKET_PER_PAGE + 1);
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(new URL(String(fetchFn.mock.calls[1]![0])).hostname).toBe('api.bitbucket.org');
  });

  it('succeeds when the only page is full and next is absent', async () => {
    setToken();
    const full = Array.from({ length: BITBUCKET_PER_PAGE }, (_, i) =>
      repo({ slug: `repo-${i}`, name: `repo-${i}`, full_name: `langell/repo-${i}` }),
    );
    const fetchFn = vi.fn(async () => new Response(JSON.stringify(page(full)), { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);
    const assets = await collect(new BitbucketConnector().discover(ctx(cfg())));
    expect(assets).toHaveLength(BITBUCKET_PER_PAGE);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('fails when a leftover next remains at the page cap', async () => {
    setToken();
    const fetchFn = vi.fn(async (url: string) => {
      const pageNo = Number(new URL(String(url)).searchParams.get('page') ?? '1');
      const values = Array.from({ length: 1 }, (_, i) =>
        repo({ slug: `r-${pageNo}-${i}`, name: `r-${pageNo}-${i}`, full_name: `langell/r-${pageNo}-${i}` }),
      );
      const next =
        pageNo <= BITBUCKET_MAX_PAGES
          ? `https://api.bitbucket.org/2.0/repositories/langell?pagelen=100&page=${pageNo + 1}`
          : undefined;
      return new Response(JSON.stringify(page(values, next)), { status: 200 });
    });
    vi.stubGlobal('fetch', fetchFn);
    await expect(collect(new BitbucketConnector().discover(ctx(cfg())))).rejects.toThrow(/truncated/);
    expect(fetchFn).toHaveBeenCalledTimes(BITBUCKET_MAX_PAGES);
  });

  it('refuses an off-allowlist next and never sends the bearer there', async () => {
    setToken();
    const fetchFn = vi.fn(async () =>
      new Response(
        JSON.stringify(page([repo()], 'https://evil.example/2.0/repositories/langell?page=2')),
        { status: 200 },
      ),
    );
    vi.stubGlobal('fetch', fetchFn);
    await expect(collect(new BitbucketConnector().discover(ctx(cfg())))).rejects.toThrow(
      /only api\.bitbucket\.org is allowlisted/,
    );
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(new URL(String(fetchFn.mock.calls[0]![0])).hostname).toBe('api.bitbucket.org');
  });

  it('refuses tenant baseUrl, bitbucketUrl, host, apiUrl, and authority before fetch', async () => {
    setToken();
    const fetchFn = vi.fn(async () => new Response(JSON.stringify(page([repo()])), { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);
    for (const key of ['baseUrl', 'bitbucketUrl', 'host', 'apiUrl', 'authority']) {
      await expect(
        collect(new BitbucketConnector().discover(ctx(cfg({ [key]: 'https://bitbucket.internal' })))),
      ).rejects.toThrow(/tenant-writable Bitbucket endpoint/);
    }
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('requires workspace and rejects a string allowlist', async () => {
    setToken();
    await expect(collect(new BitbucketConnector().discover(ctx({})))).rejects.toThrow(/workspace/);
    await expect(
      collect(new BitbucketConnector().discover(ctx(cfg({ repos: 'ctem-scan-target' })))),
    ).rejects.toThrow();
    await expect(
      collect(new BitbucketConnector().discover(ctx(cfg({ includeArchived: 'false' })))),
    ).rejects.toThrow();
  });

  it('fails closed when BITBUCKET_* credentials are missing and does not list', async () => {
    const fetchFn = vi.fn(async () => new Response(JSON.stringify(page([repo()])), { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);
    await expect(collect(new BitbucketConnector().discover(ctx(cfg())))).rejects.toThrow(/cannot be used/);
    await expect(collect(new BitbucketConnector().discover(ctx(cfg(), null)))).rejects.toThrow(
      /env:BITBUCKET_\*/,
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses env:GITHUB_* and env:DATABASE_URL without listing', async () => {
    setToken();
    process.env.GITHUB_TOKEN = 'ghp_test';
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    const fetchFn = vi.fn(async () => new Response(JSON.stringify(page([])), { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);
    await expect(collect(new BitbucketConnector().discover(ctx(cfg(), 'env:GITHUB_TOKEN')))).rejects.toThrow(
      /env:BITBUCKET_\*/,
    );
    await expect(collect(new BitbucketConnector().discover(ctx(cfg(), 'env:DATABASE_URL')))).rejects.toThrow(
      /not allowlisted/,
    );
    await expect(collect(new BitbucketConnector().discover(ctx(cfg(), 'vault:bb')))).rejects.toThrow(
      /Unsupported credentialRef scheme/,
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('surfaces API failures so the scheduler records them', async () => {
    setToken();
    vi.stubGlobal('fetch', vi.fn(async () => new Response('no', { status: 403 })));
    await expect(collect(new BitbucketConnector().discover(ctx(cfg())))).rejects.toThrow(/403/);
  });

  it('refuses a non-object listing instead of empty-succeeding', async () => {
    setToken();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([]), { status: 200 })));
    await expect(collect(new BitbucketConnector().discover(ctx(cfg())))).rejects.toThrow(/not a JSON object/);
  });

  it('fails the sync when the bitbucket circuit is open', async () => {
    setToken();
    useInventoryEgressPolicy(
      new InternalHttpPolicy(
        { ...DEFAULT_CIRCUIT_BREAKER_CONFIG, failureThreshold: 1, maxAttempts: 1, baseDelayMs: 1 },
        { sleep: async () => undefined, random: () => 0 },
      ),
    );
    const fetchFn = vi.fn(async () => new Response('down', { status: 503 }));
    vi.stubGlobal('fetch', fetchFn);

    await expect(collect(new BitbucketConnector().discover(ctx(cfg())))).rejects.toThrow(/503/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    fetchFn.mockClear();

    await expect(collect(new BitbucketConnector().discover(ctx(cfg())))).rejects.toBeInstanceOf(
      CircuitOpenError,
    );
    await expect(collect(new BitbucketConnector().discover(ctx(cfg())))).rejects.toMatchObject({
      name: 'CircuitOpenError',
      circuit: EGRESS_BITBUCKET_API,
    });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('keeps allowlist refusal ahead of the policy and does not open the circuit', async () => {
    setToken();
    useInventoryEgressPolicy(
      new InternalHttpPolicy(
        { ...DEFAULT_CIRCUIT_BREAKER_CONFIG, failureThreshold: 1, maxAttempts: 1, baseDelayMs: 1 },
        { sleep: async () => undefined, random: () => 0 },
      ),
    );
    const fetchFn = vi.fn(async () => new Response(JSON.stringify(page([])), { status: 200 }));
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      collect(new BitbucketConnector().discover(ctx(cfg({ baseUrl: 'https://bitbucket.internal' })))),
    ).rejects.toThrow(/tenant-writable Bitbucket endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();

    await expect(collect(new BitbucketConnector().discover(ctx(cfg())))).resolves.toEqual([]);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(new URL(String(fetchFn.mock.calls[0]![0])).hostname).toBe('api.bitbucket.org');
  });
});

describe('truncation does not archiveStale', () => {
  it('leaves archiveStale uncalled when a leftover next remains at the cap', async () => {
    setToken();
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        const pageNo = Number(new URL(String(url)).searchParams.get('page') ?? '1');
        return new Response(
          JSON.stringify(
            page(
              [repo({ slug: `r-${pageNo}`, name: `r-${pageNo}`, full_name: `langell/r-${pageNo}` })],
              `https://api.bitbucket.org/2.0/repositories/langell?pagelen=100&page=${pageNo + 1}`,
            ),
          ),
          { status: 200 },
        );
      }),
    );
    const registry = new ConnectorRegistry();
    registry.register(new BitbucketConnector());
    const upsert = vi.fn(async () => undefined);
    const archiveStale = vi.fn(async () => ({ count: 0 }));
    const prisma = {
      withOrg: vi.fn(async (_orgId: string, fn: (tx: { integration: { update: ReturnType<typeof vi.fn> } }) => unknown) =>
        fn({ integration: { update: vi.fn() } }),
      ),
    };
    const scheduler = new DiscoverySchedulerService(
      prisma as unknown as PrismaService,
      registry,
      { upsert, archiveStale } as never,
    );

    const result = await scheduler.syncIntegration({
      id: 'int-1',
      orgId: 'org-1',
      provider: 'bitbucket',
      config: { workspace: 'langell' },
      credentialRef: 'env:BITBUCKET_TOKEN',
      lastSyncAt: null,
    });

    expect(result.error).toMatch(/truncated/);
    expect(result.archived).toBe(0);
    expect(archiveStale).not.toHaveBeenCalled();
  });
});

import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  GHCR_MAX_PAGES,
  GHCR_PER_PAGE,
  GhcrConnector,
  imageToAsset,
  parseVersions,
  versionDigest,
  type GhcrImage,
} from './ghcr.connector';
import type { DiscoveryContext } from './connector.registry';

const DIGEST_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

const ctx = (
  config: Record<string, unknown> = { owner: 'acme', ownerType: 'org' },
  credentialRef: string | null = 'env:GITHUB_TOKEN',
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

function pkg(name: string, over: Record<string, unknown> = {}): object {
  return {
    name,
    package_type: 'container',
    visibility: 'private',
    html_url: `https://github.com/orgs/acme/packages/container/package/${name}`,
    owner: { login: 'acme' },
    ...over,
  };
}

function version(digest: string, tags: string[] = ['latest']): object {
  return {
    id: digest.slice(-8),
    name: digest,
    metadata: { package_type: 'container', container: { tags } },
  };
}

function linkNext(url: string): string {
  return `<${url}>; rel="next"`;
}

function stubGhcr(opts: {
  packages?: object[][];
  versions?: Record<string, object[][]>;
  packageNext?: Array<string | undefined>;
  versionNext?: Record<string, Array<string | undefined>>;
  status?: number;
  versionStatus?: number;
}): ReturnType<typeof vi.fn> {
  const packagePage = { n: 0 };
  const versionPage: Record<string, number> = {};
  const fn = vi.fn(async (url: string | URL) => {
    const parsed = new URL(String(url));
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (parsed.pathname.includes('/versions')) {
      if (opts.versionStatus && opts.versionStatus !== 200) {
        return new Response('boom', { status: opts.versionStatus });
      }
      const match = parsed.pathname.match(/\/packages\/container\/([^/]+)\/versions$/);
      const name = decodeURIComponent(match?.[1] ?? '');
      const page = versionPage[name] ?? 0;
      const pages = opts.versions?.[name] ?? [[]];
      const body = pages[page] ?? [];
      const more = page < pages.length - 1;
      const next =
        opts.versionNext?.[name]?.[page] ??
        (more
          ? `https://api.github.com/orgs/acme/packages/container/${encodeURIComponent(name)}/versions?page=${page + 2}`
          : undefined);
      versionPage[name] = page + 1;
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: next ? { link: linkNext(next) } : {},
      });
    }
    if (parsed.pathname.endsWith('/packages')) {
      const page = packagePage.n;
      const pages = opts.packages ?? [[]];
      const body = pages[page] ?? [];
      const more = page < pages.length - 1;
      const next =
        opts.packageNext?.[page] ??
        (more ? `https://api.github.com/orgs/acme/packages?package_type=container&page=${page + 2}` : undefined);
      packagePage.n += 1;
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: next ? { link: linkNext(next) } : {},
      });
    }
    return new Response('unexpected', { status: 500 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function setGithubToken(): void {
  process.env.GITHUB_TOKEN = 'ghp_test';
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.GITHUB_TOKEN;
  delete process.env.GITHUB_TEST_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
});

describe('imageToAsset / versionDigest', () => {
  it('maps identity as container_image keyed by digest, not tag', () => {
    const image: GhcrImage = {
      owner: 'acme',
      packageName: 'payments-api',
      digest: DIGEST_A,
      tags: ['latest', 'v1'],
      visibility: 'private',
    };
    expect(imageToAsset(image)).toMatchObject({
      kind: 'container_image',
      externalKey: `ghcr:acme/payments-api@${DIGEST_A}`,
      name: 'acme/payments-api',
      source: 'ghcr',
      exposure: 'internal',
      attributes: { digest: DIGEST_A, tags: ['latest', 'v1'], package: 'payments-api' },
    });
    expect(imageToAsset({ ...image, visibility: 'public' }).exposure).toBe('internet_facing');
    expect(versionDigest({ name: DIGEST_A })).toBe(DIGEST_A);
    expect(versionDigest({ name: 'latest' })).toBeUndefined();
    expect(versionDigest({ name: 'v1.2.3' })).toBeUndefined();
  });

  it('does not treat a tag as a digest identity', () => {
    expect(parseVersions([{ name: 'latest', metadata: { container: { tags: ['latest'] } } }])).toEqual(
      [],
    );
    expect(
      parseVersions([
        { name: DIGEST_A, metadata: { package_type: 'container', container: { tags: ['latest'] } } },
      ]),
    ).toEqual([{ digest: DIGEST_A, tags: ['latest'] }]);
  });
});

describe('GhcrConnector.discover', () => {
  it('inventories container packages as digest-keyed container_image assets on api.github.com', async () => {
    setGithubToken();
    const fetchFn = stubGhcr({
      packages: [[pkg('payments-api'), pkg('worker')]],
      versions: {
        'payments-api': [[version(DIGEST_A, ['latest', 'v1'])]],
        worker: [[version(DIGEST_B, ['stable'])]],
      },
    });
    const assets = (await collect(new GhcrConnector().discover(ctx()))) as Array<{
      kind: string;
      source: string;
      externalKey: string;
      attributes: { tags: string[]; digest: string };
    }>;
    expect(assets.every((a) => a.kind === 'container_image')).toBe(true);
    expect(assets.every((a) => a.source === 'ghcr')).toBe(true);
    expect(assets.map((a) => a.externalKey)).toEqual([
      `ghcr:acme/payments-api@${DIGEST_A}`,
      `ghcr:acme/worker@${DIGEST_B}`,
    ]);
    expect(assets[0]?.attributes.tags).toEqual(['latest', 'v1']);
    expect(assets.every((a) => a.kind !== 'repository')).toBe(true);

    for (const [url] of fetchFn.mock.calls) {
      const parsed = new URL(String(url));
      expect(parsed.hostname).toBe('api.github.com');
      expect(parsed.protocol).toBe('https:');
      expect(parsed.hostname).not.toBe('ghcr.io');
      expect(parsed.pathname).not.toMatch(/\/blobs?\//);
      expect(parsed.pathname).not.toMatch(/\/v2\//);
      expect(parsed.pathname).not.toMatch(/\/manifests\//);
    }
    expect(String(fetchFn.mock.calls[0][0])).toBe(
      'https://api.github.com/orgs/acme/packages?package_type=container&per_page=100',
    );
    expect((fetchFn.mock.calls[0][1] as RequestInit).headers).toMatchObject({
      authorization: 'Bearer ghp_test',
    });
  });

  it('lists user packages when ownerType is user', async () => {
    setGithubToken();
    const fetchFn = stubGhcr({
      packages: [[pkg('hello', { owner: { login: 'octocat' } })]],
      versions: { hello: [[version(DIGEST_A)]] },
    });
    await collect(new GhcrConnector().discover(ctx({ owner: 'octocat', ownerType: 'user' })));
    expect(String(fetchFn.mock.calls[0][0])).toContain('/users/octocat/packages');
  });

  it('keeps one asset when the same digest is retagged', async () => {
    setGithubToken();
    stubGhcr({
      packages: [[pkg('payments-api')]],
      versions: {
        'payments-api': [[version(DIGEST_A, ['latest']), version(DIGEST_A, ['v2'])]],
      },
    });
    const assets = (await collect(new GhcrConnector().discover(ctx()))) as Array<{
      externalKey: string;
    }>;
    expect(assets).toHaveLength(1);
    expect(assets[0]?.externalKey).toBe(`ghcr:acme/payments-api@${DIGEST_A}`);
  });

  it('does not invent a container_image from tags alone', async () => {
    setGithubToken();
    stubGhcr({
      packages: [[pkg('payments-api')]],
      versions: {
        'payments-api': [[{ name: 'latest', metadata: { container: { tags: ['latest'] } } }]],
      },
    });
    const assets = await collect(new GhcrConnector().discover(ctx()));
    expect(assets).toHaveLength(0);
  });

  it('honors the packages allowlist', async () => {
    setGithubToken();
    stubGhcr({
      packages: [[pkg('payments-api'), pkg('other')]],
      versions: {
        'payments-api': [[version(DIGEST_A)]],
        other: [[version(DIGEST_B)]],
      },
    });
    const assets = (await collect(
      new GhcrConnector().discover(ctx({ owner: 'acme', ownerType: 'org', packages: ['payments-api'] })),
    )) as Array<{ externalKey: string }>;
    expect(assets.map((a) => a.externalKey)).toEqual([`ghcr:acme/payments-api@${DIGEST_A}`]);
  });

  it('requires ownerType', async () => {
    setGithubToken();
    await expect(collect(new GhcrConnector().discover(ctx({ owner: 'acme' })))).rejects.toThrow(
      /ownerType/,
    );
  });

  it('succeeds on a last page of GHCR_PER_PAGE with no Link next', async () => {
    setGithubToken();
    const names = Array.from({ length: GHCR_PER_PAGE }, (_, i) => `img-${i}`);
    const digestFor = (i: number) =>
      `sha256:${i.toString(16).padStart(2, '0')}${'a'.repeat(62)}` as const;
    const fetchFn = stubGhcr({
      packages: [names.map((name) => pkg(name))],
      versions: Object.fromEntries(names.map((name, i) => [name, [[version(digestFor(i))]]])),
    });
    const assets = await collect(new GhcrConnector().discover(ctx()));
    expect(assets).toHaveLength(GHCR_PER_PAGE);
    const packageCalls = fetchFn.mock.calls.filter(([url]) =>
      /\/packages(?:\?|$)/.test(new URL(String(url)).pathname + '?'),
    );
    expect(packageCalls).toHaveLength(1);
  });

  it('fails when a package listing is truncated at the page cap', async () => {
    setGithubToken();
    const pages = Array.from({ length: GHCR_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: GHCR_PER_PAGE }, (_, i) => pkg(`img-${p}-${i}`)),
    );
    const fetchFn = stubGhcr({ packages: pages, versions: {} });
    await expect(collect(new GhcrConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const packageCalls = fetchFn.mock.calls.filter(([url]) => String(url).includes('/packages?'));
    expect(packageCalls).toHaveLength(GHCR_MAX_PAGES);
  });

  it('fails when a versions listing is truncated at the page cap', async () => {
    setGithubToken();
    const pages = Array.from({ length: GHCR_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: GHCR_PER_PAGE }, (_, i) => {
        const hex = `${p.toString(16).padStart(2, '0')}${i.toString(16).padStart(2, '0')}${'b'.repeat(60)}`;
        return version(`sha256:${hex}`);
      }),
    );
    const fetchFn = stubGhcr({
      packages: [[pkg('payments-api')]],
      versions: { 'payments-api': pages },
    });
    await expect(collect(new GhcrConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const versionCalls = fetchFn.mock.calls.filter(([url]) => String(url).includes('/versions'));
    expect(versionCalls).toHaveLength(GHCR_MAX_PAGES);
  });

  it('refuses an off-allowlist Link next and never sends the bearer there', async () => {
    setGithubToken();
    const fetchFn = stubGhcr({
      packages: [[pkg('payments-api')]],
      packageNext: ['https://evil.example/packages?page=2'],
    });
    await expect(collect(new GhcrConnector().discover(ctx()))).rejects.toThrow(/only api\.github\.com/);
    for (const [url] of fetchFn.mock.calls) {
      expect(String(url)).not.toContain('evil.example');
      expect(new URL(String(url)).hostname).toBe('api.github.com');
    }
  });

  it('fails closed when GITHUB_* credentials are missing', async () => {
    const fetchFn = stubGhcr({ packages: [[pkg('payments-api')]] });
    await expect(collect(new GhcrConnector().discover(ctx()))).rejects.toThrow(/cannot be used/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when credentialRef is unset — no unauthenticated listing', async () => {
    setGithubToken();
    const fetchFn = stubGhcr({ packages: [[pkg('payments-api')]] });
    await expect(
      collect(new GhcrConnector().discover(ctx({ owner: 'acme', ownerType: 'org' }, null))),
    ).rejects.toThrow(/env:GITHUB_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses env:AWS_* even when a GITHUB_TOKEN is present', async () => {
    setGithubToken();
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    const fetchFn = stubGhcr({ packages: [[pkg('payments-api')]] });
    await expect(
      collect(new GhcrConnector().discover(ctx({ owner: 'acme', ownerType: 'org' }, 'env:AWS_ACCESS_KEY_ID'))),
    ).rejects.toThrow(/env:GITHUB_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses a tenant-writable endpoint and never sends keys there', async () => {
    setGithubToken();
    const fetchFn = stubGhcr({ packages: [[pkg('payments-api')]] });
    await expect(
      collect(
        new GhcrConnector().discover(
          ctx({
            owner: 'acme',
            ownerType: 'org',
            endpoint: 'https://evil.example',
            apiUrl: 'https://evil.example/github',
            registryUrl: 'https://ghcr.io',
            ghcrUrl: 'https://ghcr.io/v2/',
            baseUrl: 'https://api.github.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable GHCR endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('does not take a tenant-supplied host even when mixed with a valid owner', async () => {
    setGithubToken();
    const fetchFn = stubGhcr({ packages: [[pkg('payments-api')]] });
    await expect(
      collect(
        new GhcrConnector().discover(
          ctx({
            owner: 'acme',
            ownerType: 'org',
            host: 'ghcr.io',
            customEndpoint: 'https://api.github.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable GHCR endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    setGithubToken();
    stubGhcr({ status: 403 });
    await expect(collect(new GhcrConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('fails closed when versions listing is incomplete after packages succeeded', async () => {
    setGithubToken();
    stubGhcr({
      packages: [[pkg('payments-api')]],
      versions: { 'payments-api': [[version(DIGEST_A)]] },
      versionStatus: 403,
    });
    await expect(collect(new GhcrConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(
      collect(new GhcrConnector().discover(ctx({ owner: 'acme', ownerType: 'org' }, 'vault:gh'))),
    ).rejects.toThrow(/Unsupported credentialRef scheme/);
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret', async () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    await expect(
      collect(new GhcrConnector().discover(ctx({ owner: 'acme', ownerType: 'org' }, 'env:DATABASE_URL'))),
    ).rejects.toThrow(/not allowlisted/);
  });

  it('does not contain layer/blob download in the connector source', () => {
    const src = readFileSync(join(__dirname, 'ghcr.connector.ts'), 'utf8');
    expect(src).not.toMatch(/ghcr\.io/);
    expect(src).not.toMatch(/\/blobs\//);
    expect(src).not.toMatch(/\/manifests\//);
    expect(src).not.toMatch(/application\/vnd\.oci/);
    expect(src).toMatch(/api\.github\.com|allowlistedGithubApiUrl/);
  });
});

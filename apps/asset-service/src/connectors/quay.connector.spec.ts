import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  QUAY_MAX_PAGES,
  QUAY_PER_PAGE,
  QuayConnector,
  imageDigest,
  imageToAsset,
  parseTags,
  type QuayImage,
} from './quay.connector';
import type { DiscoveryContext } from './connector.registry';

const DIGEST_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

const ctx = (
  config: Record<string, unknown> = { namespace: 'acme' },
  credentialRef: string | null = 'env:QUAY_TOKEN',
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

function repo(name: string, over: Record<string, unknown> = {}): object {
  return {
    namespace: 'acme',
    name,
    is_public: false,
    kind: 'image',
    state: 'NORMAL',
    ...over,
  };
}

function tag(digest: string, name = 'latest', over: Record<string, unknown> = {}): object {
  return {
    name,
    manifest_digest: digest,
    is_manifest_list: false,
    size: 1024,
    ...over,
  };
}

function stubQuay(opts: {
  repositories?: object[][];
  tags?: Record<string, object[][]>;
  repoNext?: Array<string | undefined>;
  tagHasAdditional?: Record<string, boolean[]>;
  status?: number;
  tagStatus?: number;
}): ReturnType<typeof vi.fn> {
  const repoPage = { n: 0 };
  const tagPage: Record<string, number> = {};
  const fn = vi.fn(async (url: string | URL) => {
    const parsed = new URL(String(url));
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (parsed.pathname.endsWith('/tag') || parsed.pathname.includes('/tag')) {
      if (opts.tagStatus && opts.tagStatus !== 200) {
        return new Response('boom', { status: opts.tagStatus });
      }
      const match = parsed.pathname.match(/\/repository\/acme\/(.+)\/tag$/);
      const name = decodeURIComponent((match?.[1] ?? '').replace(/\//g, '/'));
      const page = tagPage[name] ?? 0;
      const pages = opts.tags?.[name] ?? [[]];
      const body = pages[page] ?? [];
      const more = page < pages.length - 1;
      const hasAdditional = opts.tagHasAdditional?.[name]?.[page] ?? more;
      tagPage[name] = page + 1;
      return new Response(
        JSON.stringify({ tags: body, page: page + 1, has_additional: hasAdditional }),
        { status: 200 },
      );
    }
    if (parsed.pathname.endsWith('/repository') || parsed.pathname.endsWith('/repository/')) {
      const page = repoPage.n;
      const pages = opts.repositories ?? [[]];
      const body = pages[page] ?? [];
      const more = page < pages.length - 1;
      const next =
        opts.repoNext?.[page] ?? (more ? `repo-token-${page + 1}` : undefined);
      repoPage.n += 1;
      return new Response(
        JSON.stringify({ repositories: body, ...(next ? { next_page: next } : {}) }),
        { status: 200 },
      );
    }
    return new Response('unexpected', { status: 500 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function setQuayToken(): void {
  process.env.QUAY_TOKEN = 'quay_test';
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.QUAY_TOKEN;
  delete process.env.QUAY_TEST_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.GITHUB_TOKEN;
});

describe('imageToAsset / imageDigest', () => {
  it('maps identity as container_image keyed by digest, not tag', () => {
    const image: QuayImage = {
      namespace: 'acme',
      repository: 'payments-api',
      digest: DIGEST_A,
      tags: ['latest', 'v1'],
      isPublic: false,
    };
    expect(imageToAsset(image)).toMatchObject({
      kind: 'container_image',
      externalKey: `quay:acme/payments-api@${DIGEST_A}`,
      name: 'acme/payments-api',
      source: 'quay',
      exposure: 'internal',
      attributes: { digest: DIGEST_A, tags: ['latest', 'v1'], repository: 'payments-api' },
    });
    expect(imageToAsset({ ...image, isPublic: true }).exposure).toBe('internet_facing');
    expect(imageDigest(DIGEST_A)).toBe(DIGEST_A);
    expect(imageDigest('latest')).toBeUndefined();
    expect(imageDigest('v1.2.3')).toBeUndefined();
  });

  it('does not treat a tag as a digest identity', () => {
    expect(parseTags({ tags: [{ name: 'latest', manifest_digest: 'latest' }] })).toEqual([]);
    expect(
      parseTags({
        tags: [{ name: 'latest', manifest_digest: DIGEST_A }],
      }),
    ).toEqual([expect.objectContaining({ digest: DIGEST_A, name: 'latest' })]);
  });
});

describe('QuayConnector.discover', () => {
  it('inventories Quay tags as digest-keyed container_image assets on quay.io /api/v1', async () => {
    setQuayToken();
    const fetchFn = stubQuay({
      repositories: [[repo('payments-api'), repo('worker')]],
      tags: {
        'payments-api': [[tag(DIGEST_A, 'latest'), tag(DIGEST_A, 'v1')]],
        worker: [[tag(DIGEST_B, 'stable')]],
      },
    });
    const assets = (await collect(new QuayConnector().discover(ctx()))) as Array<{
      kind: string;
      source: string;
      externalKey: string;
      attributes: { tags: string[]; digest: string };
    }>;
    expect(assets.every((a) => a.kind === 'container_image')).toBe(true);
    expect(assets.every((a) => a.source === 'quay')).toBe(true);
    expect(assets.map((a) => a.externalKey)).toEqual([
      `quay:acme/payments-api@${DIGEST_A}`,
      `quay:acme/worker@${DIGEST_B}`,
    ]);
    expect(assets[0]?.attributes.tags).toEqual(['latest', 'v1']);
    expect(assets.every((a) => a.kind !== 'repository')).toBe(true);

    for (const [url] of fetchFn.mock.calls) {
      const parsed = new URL(String(url));
      expect(parsed.hostname).toBe('quay.io');
      expect(parsed.protocol).toBe('https:');
      expect(parsed.pathname.startsWith('/api/v1/')).toBe(true);
      expect(parsed.pathname).not.toMatch(/\/blobs\//);
      expect(parsed.pathname).not.toMatch(/\/v2\//);
      expect(parsed.pathname).not.toMatch(/\/manifests\//);
    }
    expect(String(fetchFn.mock.calls[0][0])).toBe(
      'https://quay.io/api/v1/repository?namespace=acme&repo_kind=image',
    );
    expect((fetchFn.mock.calls[0][1] as RequestInit).headers).toMatchObject({
      authorization: 'Bearer quay_test',
    });
  });

  it('keeps one asset when the same digest is retagged', async () => {
    setQuayToken();
    stubQuay({
      repositories: [[repo('payments-api')]],
      tags: {
        'payments-api': [[tag(DIGEST_A, 'latest'), tag(DIGEST_A, 'v2')]],
      },
    });
    const assets = (await collect(new QuayConnector().discover(ctx()))) as Array<{
      externalKey: string;
      attributes: { tags: string[] };
    }>;
    expect(assets).toHaveLength(1);
    expect(assets[0]?.externalKey).toBe(`quay:acme/payments-api@${DIGEST_A}`);
    expect(assets[0]?.attributes.tags).toEqual(['latest', 'v2']);
  });

  it('does not invent a container_image from tags alone', async () => {
    setQuayToken();
    stubQuay({
      repositories: [[repo('payments-api')]],
      tags: {
        'payments-api': [[{ name: 'latest', manifest_digest: 'latest' }]],
      },
    });
    const assets = await collect(new QuayConnector().discover(ctx()));
    expect(assets).toHaveLength(0);
  });

  it('honors the repositories allowlist', async () => {
    setQuayToken();
    stubQuay({
      repositories: [[repo('payments-api'), repo('other')]],
      tags: {
        'payments-api': [[tag(DIGEST_A)]],
        other: [[tag(DIGEST_B)]],
      },
    });
    const assets = (await collect(
      new QuayConnector().discover(ctx({ namespace: 'acme', repositories: ['payments-api'] })),
    )) as Array<{ externalKey: string }>;
    expect(assets.map((a) => a.externalKey)).toEqual([`quay:acme/payments-api@${DIGEST_A}`]);
  });

  it('requires namespace', async () => {
    setQuayToken();
    await expect(collect(new QuayConnector().discover(ctx({})))).rejects.toThrow(/namespace/);
  });

  it('succeeds on a last page of QUAY_PER_PAGE with no leftover next', async () => {
    setQuayToken();
    const names = Array.from({ length: QUAY_PER_PAGE }, (_, i) => `img-${i}`);
    const digestFor = (i: number) =>
      `sha256:${i.toString(16).padStart(2, '0')}${'a'.repeat(62)}` as const;
    const fetchFn = stubQuay({
      repositories: [names.map((name) => repo(name))],
      tags: Object.fromEntries(names.map((name, i) => [name, [[tag(digestFor(i))]]])),
    });
    const assets = await collect(new QuayConnector().discover(ctx()));
    expect(assets).toHaveLength(QUAY_PER_PAGE);
    const repoCalls = fetchFn.mock.calls.filter(([url]) => {
      const parsed = new URL(String(url));
      return parsed.pathname === '/api/v1/repository';
    });
    expect(repoCalls).toHaveLength(1);
  });

  it('fails when a repository listing is truncated at the page cap', async () => {
    setQuayToken();
    const pages = Array.from({ length: QUAY_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: QUAY_PER_PAGE }, (_, i) => repo(`img-${p}-${i}`)),
    );
    const fetchFn = stubQuay({ repositories: pages, tags: {} });
    await expect(collect(new QuayConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const repoCalls = fetchFn.mock.calls.filter(([url]) => {
      const parsed = new URL(String(url));
      return parsed.pathname === '/api/v1/repository';
    });
    expect(repoCalls).toHaveLength(QUAY_MAX_PAGES);
  });

  it('fails when a tag listing is truncated at the page cap', async () => {
    setQuayToken();
    const pages = Array.from({ length: QUAY_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: QUAY_PER_PAGE }, (_, i) => {
        const hex = `${p.toString(16).padStart(2, '0')}${i.toString(16).padStart(2, '0')}${'b'.repeat(60)}`;
        return tag(`sha256:${hex}`, `t-${p}-${i}`);
      }),
    );
    const fetchFn = stubQuay({
      repositories: [[repo('payments-api')]],
      tags: { 'payments-api': pages },
    });
    await expect(collect(new QuayConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const tagCalls = fetchFn.mock.calls.filter(([url]) => String(url).includes('/tag'));
    expect(tagCalls).toHaveLength(QUAY_MAX_PAGES);
  });

  it('refuses an off-allowlist next_page URL and never sends the bearer there', async () => {
    setQuayToken();
    const fetchFn = stubQuay({
      repositories: [[repo('payments-api')]],
      repoNext: ['https://evil.example/api/v1/repository?page=2'],
    });
    await expect(collect(new QuayConnector().discover(ctx()))).rejects.toThrow(/only quay\.io/);
    for (const [url] of fetchFn.mock.calls) {
      expect(String(url)).not.toContain('evil.example');
      expect(new URL(String(url)).hostname).toBe('quay.io');
    }
  });

  it('fails closed when QUAY_* credentials are missing', async () => {
    const fetchFn = stubQuay({ repositories: [[repo('payments-api')]] });
    await expect(collect(new QuayConnector().discover(ctx()))).rejects.toThrow(/cannot be used/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when credentialRef is unset — no unauthenticated listing', async () => {
    setQuayToken();
    const fetchFn = stubQuay({ repositories: [[repo('payments-api')]] });
    await expect(collect(new QuayConnector().discover(ctx({ namespace: 'acme' }, null)))).rejects.toThrow(
      /env:QUAY_\*/,
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses env:AWS_* even when a QUAY_TOKEN is present', async () => {
    setQuayToken();
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    const fetchFn = stubQuay({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(new QuayConnector().discover(ctx({ namespace: 'acme' }, 'env:AWS_ACCESS_KEY_ID'))),
    ).rejects.toThrow(/env:QUAY_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses env:GITHUB_* even when a QUAY_TOKEN is present', async () => {
    setQuayToken();
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchFn = stubQuay({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(new QuayConnector().discover(ctx({ namespace: 'acme' }, 'env:GITHUB_TOKEN'))),
    ).rejects.toThrow(/env:QUAY_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses a tenant-writable endpoint and never sends keys there', async () => {
    setQuayToken();
    const fetchFn = stubQuay({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(
        new QuayConnector().discover(
          ctx({
            namespace: 'acme',
            endpoint: 'https://evil.example',
            apiUrl: 'https://evil.example/quay',
            registryUrl: 'https://quay.io',
            quayUrl: 'https://quay.internal/api/v1/',
            baseUrl: 'https://quay.io.evil.example',
            authority: 'quay.internal',
            host: 'quay.internal',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable Quay endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('does not take a tenant-supplied host even when mixed with a valid namespace', async () => {
    setQuayToken();
    const fetchFn = stubQuay({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(
        new QuayConnector().discover(
          ctx({
            namespace: 'acme',
            host: 'quay.io',
            customEndpoint: 'https://quay.io.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable Quay endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    setQuayToken();
    stubQuay({ status: 403 });
    await expect(collect(new QuayConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('fails closed when tag listing is incomplete after repositories succeeded', async () => {
    setQuayToken();
    stubQuay({
      repositories: [[repo('payments-api')]],
      tags: { 'payments-api': [[tag(DIGEST_A)]] },
      tagStatus: 403,
    });
    await expect(collect(new QuayConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(
      collect(new QuayConnector().discover(ctx({ namespace: 'acme' }, 'vault:quay'))),
    ).rejects.toThrow(/Unsupported credentialRef scheme/);
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret', async () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    await expect(
      collect(new QuayConnector().discover(ctx({ namespace: 'acme' }, 'env:DATABASE_URL'))),
    ).rejects.toThrow(/not allowlisted/);
  });

  it('does not contain layer/blob download in the connector source', () => {
    const src = readFileSync(join(__dirname, 'quay.connector.ts'), 'utf8');
    expect(src).not.toMatch(/\/blobs\//);
    expect(src).not.toMatch(/\/v2\//);
    expect(src).not.toMatch(/application\/vnd\.oci/);
    expect(src).not.toMatch(/scanner-container-iac/);
    expect(src).not.toMatch(/\bdocker\b/);
    expect(src).toMatch(/api\/v1|allowlistedQuayApiUrl/);
  });
});

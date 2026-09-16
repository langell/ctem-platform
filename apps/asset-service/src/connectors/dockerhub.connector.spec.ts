import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  DOCKERHUB_MAX_PAGES,
  DOCKERHUB_PER_PAGE,
  DockerhubConnector,
  imageToAsset,
  parseTags,
  tagDigests,
  type DockerhubImage,
} from './dockerhub.connector';
import type { DiscoveryContext } from './connector.registry';

const DIGEST_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

const ctx = (
  config: Record<string, unknown> = { namespace: 'acme' },
  credentialRef: string | null = 'env:DOCKERHUB_TOKEN',
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
    name,
    namespace: 'acme',
    repository_type: 'image',
    is_private: true,
    ...over,
  };
}

function tag(name: string, digest: string | undefined, over: Record<string, unknown> = {}): object {
  return {
    name,
    digest,
    images: digest ? [{ architecture: 'amd64', os: 'linux', digest }] : [],
    ...over,
  };
}

function page(results: object[], next?: string): object {
  return { count: results.length, next: next ?? null, previous: null, results };
}

function stubHub(opts: {
  repositories?: object[][];
  tags?: Record<string, object[][]>;
  repoNext?: Array<string | undefined>;
  tagNext?: Record<string, Array<string | undefined>>;
  status?: number;
  tagStatus?: number;
  loginStatus?: number;
  loginToken?: string;
}): ReturnType<typeof vi.fn> {
  const repoPage = { n: 0 };
  const tagPage: Record<string, number> = {};
  const fn = vi.fn(async (url: string | URL, _init?: RequestInit) => {
    const parsed = new URL(String(url));
    const path = parsed.pathname.replace(/\/+$/, '') || '/';
    if (path === '/v2/users/login') {
      if (opts.loginStatus && opts.loginStatus !== 200) {
        return new Response('boom', { status: opts.loginStatus });
      }
      return new Response(JSON.stringify({ token: opts.loginToken ?? 'jwt-test' }), { status: 200 });
    }
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (path.endsWith('/tags')) {
      if (opts.tagStatus && opts.tagStatus !== 200) {
        return new Response('boom', { status: opts.tagStatus });
      }
      const match = path.match(/\/v2\/repositories\/[^/]+\/([^/]+)\/tags$/);
      const name = decodeURIComponent(match?.[1] ?? '');
      const n = tagPage[name] ?? 0;
      const pages = opts.tags?.[name] ?? [[]];
      const body = pages[n] ?? [];
      const more = n < pages.length - 1;
      const next =
        opts.tagNext?.[name]?.[n] ??
        (more
          ? `https://hub.docker.com/v2/repositories/acme/${encodeURIComponent(name)}/tags/?page=${n + 2}`
          : undefined);
      tagPage[name] = n + 1;
      return new Response(JSON.stringify(page(body, next)), { status: 200 });
    }
    if (path.startsWith('/v2/repositories/')) {
      const n = repoPage.n;
      const pages = opts.repositories ?? [[]];
      const body = pages[n] ?? [];
      const more = n < pages.length - 1;
      const next =
        opts.repoNext?.[n] ??
        (more ? `https://hub.docker.com/v2/repositories/acme/?page=${n + 2}` : undefined);
      repoPage.n += 1;
      return new Response(JSON.stringify(page(body, next)), { status: 200 });
    }
    return new Response('unexpected', { status: 500 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function setDockerhubCreds(): void {
  process.env.DOCKERHUB_USERNAME = 'acme';
  process.env.DOCKERHUB_TOKEN = 'dckr_pat_test';
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.DOCKERHUB_USERNAME;
  delete process.env.DOCKERHUB_TOKEN;
  delete process.env.GITHUB_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
});

describe('imageToAsset / tagDigests', () => {
  it('maps identity as container_image keyed by digest, not tag', () => {
    const image: DockerhubImage = {
      namespace: 'acme',
      repository: 'payments-api',
      digest: DIGEST_A,
      tags: ['latest', 'v1'],
      isPrivate: true,
    };
    expect(imageToAsset(image)).toMatchObject({
      kind: 'container_image',
      externalKey: `dockerhub:acme/payments-api@${DIGEST_A}`,
      name: 'acme/payments-api',
      source: 'dockerhub',
      exposure: 'internal',
      attributes: { digest: DIGEST_A, tags: ['latest', 'v1'], repository: 'payments-api' },
    });
    expect(imageToAsset({ ...image, isPrivate: false }).exposure).toBe('internet_facing');
    expect(tagDigests({ digest: DIGEST_A })).toEqual([DIGEST_A]);
    expect(tagDigests({ name: 'latest' })).toEqual([]);
    expect(tagDigests({ digest: 'latest' })).toEqual([]);
  });

  it('does not treat a tag as a digest identity', () => {
    expect(
      parseTags({
        results: [{ name: 'latest', digest: null, images: [] }],
      }),
    ).toEqual([]);
    expect(
      parseTags({
        results: [{ name: 'latest', digest: DIGEST_A, images: [{ digest: DIGEST_A }] }],
      }),
    ).toEqual([{ name: 'latest', digests: [DIGEST_A] }]);
  });
});

describe('DockerhubConnector.discover', () => {
  it('inventories Hub repositories as digest-keyed container_image assets on hub.docker.com', async () => {
    setDockerhubCreds();
    const fetchFn = stubHub({
      repositories: [[repo('payments-api'), repo('worker')]],
      tags: {
        'payments-api': [[tag('latest', DIGEST_A), tag('v1', DIGEST_A)]],
        worker: [[tag('stable', DIGEST_B)]],
      },
    });
    const assets = (await collect(new DockerhubConnector().discover(ctx()))) as Array<{
      kind: string;
      source: string;
      externalKey: string;
      attributes: { tags: string[]; digest: string };
    }>;
    expect(assets.every((a) => a.kind === 'container_image')).toBe(true);
    expect(assets.every((a) => a.source === 'dockerhub')).toBe(true);
    expect(assets.map((a) => a.externalKey)).toEqual([
      `dockerhub:acme/payments-api@${DIGEST_A}`,
      `dockerhub:acme/worker@${DIGEST_B}`,
    ]);
    expect(assets[0]?.attributes.tags).toEqual(['latest', 'v1']);
    expect(assets.every((a) => a.kind !== 'repository')).toBe(true);

    for (const [url] of fetchFn.mock.calls) {
      const parsed = new URL(String(url));
      expect(parsed.hostname).toBe('hub.docker.com');
      expect(parsed.protocol).toBe('https:');
      expect(parsed.hostname).not.toBe('registry-1.docker.io');
      expect(parsed.hostname).not.toBe('index.docker.io');
      expect(parsed.pathname).not.toMatch(/\/blobs\//);
      expect(parsed.pathname).not.toMatch(/\/manifests\//);
    }
    expect(String(fetchFn.mock.calls[0][0])).toBe('https://hub.docker.com/v2/users/login/');
    expect(JSON.parse(String((fetchFn.mock.calls[0][1] as RequestInit).body))).toEqual({
      username: 'acme',
      password: 'dckr_pat_test',
    });
    expect(String(fetchFn.mock.calls[1][0])).toBe(
      'https://hub.docker.com/v2/repositories/acme/?page_size=100',
    );
    expect((fetchFn.mock.calls[1][1] as RequestInit).headers).toMatchObject({
      authorization: 'JWT jwt-test',
    });
  });

  it('keeps one asset when the same digest is retagged', async () => {
    setDockerhubCreds();
    stubHub({
      repositories: [[repo('payments-api')]],
      tags: {
        'payments-api': [[tag('latest', DIGEST_A), tag('v2', DIGEST_A)]],
      },
    });
    const assets = (await collect(new DockerhubConnector().discover(ctx()))) as Array<{
      externalKey: string;
      attributes: { tags: string[] };
    }>;
    expect(assets).toHaveLength(1);
    expect(assets[0]?.externalKey).toBe(`dockerhub:acme/payments-api@${DIGEST_A}`);
    expect(assets[0]?.attributes.tags).toEqual(['latest', 'v2']);
  });

  it('does not invent a container_image from tags alone', async () => {
    setDockerhubCreds();
    stubHub({
      repositories: [[repo('payments-api')]],
      tags: {
        'payments-api': [[{ name: 'latest', digest: null, images: [] }]],
      },
    });
    const assets = await collect(new DockerhubConnector().discover(ctx()));
    expect(assets).toHaveLength(0);
  });

  it('honors the repositories allowlist', async () => {
    setDockerhubCreds();
    stubHub({
      repositories: [[repo('payments-api'), repo('other')]],
      tags: {
        'payments-api': [[tag('latest', DIGEST_A)]],
        other: [[tag('latest', DIGEST_B)]],
      },
    });
    const assets = (await collect(
      new DockerhubConnector().discover(ctx({ namespace: 'acme', repositories: ['payments-api'] })),
    )) as Array<{ externalKey: string }>;
    expect(assets.map((a) => a.externalKey)).toEqual([`dockerhub:acme/payments-api@${DIGEST_A}`]);
  });

  it('requires namespace', async () => {
    setDockerhubCreds();
    await expect(collect(new DockerhubConnector().discover(ctx({})))).rejects.toThrow(/namespace/);
  });

  it('succeeds on a last page of DOCKERHUB_PER_PAGE with no next', async () => {
    setDockerhubCreds();
    const names = Array.from({ length: DOCKERHUB_PER_PAGE }, (_, i) => `img-${i}`);
    const digestFor = (i: number) =>
      `sha256:${i.toString(16).padStart(2, '0')}${'a'.repeat(62)}` as const;
    const fetchFn = stubHub({
      repositories: [names.map((name) => repo(name))],
      tags: Object.fromEntries(names.map((name, i) => [name, [[tag('latest', digestFor(i))]]])),
    });
    const assets = await collect(new DockerhubConnector().discover(ctx()));
    expect(assets).toHaveLength(DOCKERHUB_PER_PAGE);
    const repoCalls = fetchFn.mock.calls.filter(([url]) => {
      const path = new URL(String(url)).pathname.replace(/\/+$/, '');
      return /^\/v2\/repositories\/[^/]+$/.test(path);
    });
    expect(repoCalls).toHaveLength(1);
  });

  it('fails when a repository listing is truncated at the page cap', async () => {
    setDockerhubCreds();
    const pages = Array.from({ length: DOCKERHUB_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: DOCKERHUB_PER_PAGE }, (_, i) => repo(`img-${p}-${i}`)),
    );
    const fetchFn = stubHub({ repositories: pages, tags: {} });
    await expect(collect(new DockerhubConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const repoCalls = fetchFn.mock.calls.filter(([url]) =>
      /\/v2\/repositories\/acme\/?(?:\?|$)/.test(String(url)),
    );
    expect(repoCalls).toHaveLength(DOCKERHUB_MAX_PAGES);
  });

  it('fails when a tags listing is truncated at the page cap', async () => {
    setDockerhubCreds();
    const pages = Array.from({ length: DOCKERHUB_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: DOCKERHUB_PER_PAGE }, (_, i) => {
        const hex = `${p.toString(16).padStart(2, '0')}${i.toString(16).padStart(2, '0')}${'b'.repeat(60)}`;
        return tag(`t-${p}-${i}`, `sha256:${hex}`);
      }),
    );
    const fetchFn = stubHub({
      repositories: [[repo('payments-api')]],
      tags: { 'payments-api': pages },
    });
    await expect(collect(new DockerhubConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const tagCalls = fetchFn.mock.calls.filter(([url]) => String(url).includes('/tags'));
    expect(tagCalls).toHaveLength(DOCKERHUB_MAX_PAGES);
  });

  it('refuses an off-allowlist next and never sends the JWT there', async () => {
    setDockerhubCreds();
    const fetchFn = stubHub({
      repositories: [[repo('payments-api')]],
      repoNext: ['https://registry-1.docker.io/v2/'],
    });
    await expect(collect(new DockerhubConnector().discover(ctx()))).rejects.toThrow(
      /only hub\.docker\.com/,
    );
    for (const [url] of fetchFn.mock.calls) {
      expect(String(url)).not.toContain('registry-1.docker.io');
      expect(String(url)).not.toContain('evil.example');
      expect(new URL(String(url)).hostname).toBe('hub.docker.com');
    }
  });

  it('fails closed when DOCKERHUB_* credentials are missing', async () => {
    const fetchFn = stubHub({ repositories: [[repo('payments-api')]] });
    await expect(collect(new DockerhubConnector().discover(ctx()))).rejects.toThrow(/cannot be used/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when credentialRef is unset — no unauthenticated listing', async () => {
    setDockerhubCreds();
    const fetchFn = stubHub({ repositories: [[repo('payments-api')]] });
    await expect(collect(new DockerhubConnector().discover(ctx({ namespace: 'acme' }, null)))).rejects.toThrow(
      /env:DOCKERHUB_\*/,
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses env:GITHUB_* even when Docker Hub keys are present', async () => {
    setDockerhubCreds();
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchFn = stubHub({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(new DockerhubConnector().discover(ctx({ namespace: 'acme' }, 'env:GITHUB_TOKEN'))),
    ).rejects.toThrow(/env:DOCKERHUB_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses a tenant-writable endpoint and never sends keys there', async () => {
    setDockerhubCreds();
    const fetchFn = stubHub({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(
        new DockerhubConnector().discover(
          ctx({
            namespace: 'acme',
            endpoint: 'https://evil.example',
            apiUrl: 'https://evil.example/docker',
            registryUrl: 'https://registry-1.docker.io',
            hubUrl: 'https://hub.docker.com',
            indexUrl: 'https://index.docker.io',
            baseUrl: 'https://hub.docker.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable Docker Hub endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('does not take a tenant-supplied host even when mixed with a valid namespace', async () => {
    setDockerhubCreds();
    const fetchFn = stubHub({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(
        new DockerhubConnector().discover(
          ctx({
            namespace: 'acme',
            host: 'registry-1.docker.io',
            authority: 'index.docker.io',
            customEndpoint: 'https://hub.docker.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable Docker Hub endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    setDockerhubCreds();
    stubHub({ status: 403 });
    await expect(collect(new DockerhubConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('fails closed when tags listing is incomplete after repositories succeeded', async () => {
    setDockerhubCreds();
    stubHub({
      repositories: [[repo('payments-api')]],
      tags: { 'payments-api': [[tag('latest', DIGEST_A)]] },
      tagStatus: 403,
    });
    await expect(collect(new DockerhubConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(
      collect(new DockerhubConnector().discover(ctx({ namespace: 'acme' }, 'vault:dh'))),
    ).rejects.toThrow(/Unsupported credentialRef scheme/);
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret', async () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    await expect(
      collect(new DockerhubConnector().discover(ctx({ namespace: 'acme' }, 'env:DATABASE_URL'))),
    ).rejects.toThrow(/not allowlisted/);
  });

  it('does not contain layer/blob download in the connector source', () => {
    const src = readFileSync(join(__dirname, 'dockerhub.connector.ts'), 'utf8');
    expect(src).not.toMatch(/registry-1\.docker\.io/);
    expect(src).not.toMatch(/index\.docker\.io/);
    expect(src).not.toMatch(/\/blobs\//);
    expect(src).not.toMatch(/\/manifests\//);
    expect(src).not.toMatch(/application\/vnd\.oci/);
    expect(src).not.toMatch(/scanner-container-iac/);
    expect(src).toMatch(/hub\.docker\.com|allowlistedDockerhubUrl/);
  });
});

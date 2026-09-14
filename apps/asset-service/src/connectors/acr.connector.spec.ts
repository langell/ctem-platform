import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  ACR_MAX_PAGES,
  ACR_PER_PAGE,
  AcrConnector,
  imageDigest,
  imageToAsset,
  parseManifests,
  type AcrImage,
} from './acr.connector';
import type { DiscoveryContext } from './connector.registry';

const SUB = '11111111-1111-1111-1111-111111111111';
const TENANT = '22222222-2222-2222-2222-222222222222';
const CLIENT = '33333333-3333-3333-3333-333333333333';
const RG = 'rg-prod';
const REGISTRY = 'acmeprod';
const LOGIN = 'acmeprod.azurecr.io';
const DIGEST_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

const ctx = (
  config: Record<string, unknown> = { subscriptionId: SUB },
  credentialRef: string | null = 'env:AZURE_CLIENT_ID',
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

function armRegistry(name: string, loginServer = `${name}.azurecr.io`, rg = RG): object {
  return {
    name,
    id: `/subscriptions/${SUB}/resourceGroups/${rg}/providers/Microsoft.ContainerRegistry/registries/${name}`,
    location: 'eastus',
    properties: { loginServer },
  };
}

function manifest(digest: string, tags: string[] = ['latest']): object {
  return { digest, tags, imageSize: 1024, architecture: 'amd64', os: 'linux' };
}

function stubAcr(opts: {
  registries?: object[][];
  catalog?: string[][];
  manifests?: Record<string, object[][]>;
  registryNext?: Array<string | undefined>;
  catalogNext?: Array<string | undefined>;
  manifestNext?: Record<string, Array<string | undefined>>;
  status?: number;
  tokenStatus?: number;
  catalogStatus?: number;
  manifestStatus?: number;
}): ReturnType<typeof vi.fn> {
  const registryPage = { n: 0 };
  const catalogPage = { n: 0 };
  const manifestPage: Record<string, number> = {};
  const fn = vi.fn(async (url: string | URL, _init?: RequestInit) => {
    const parsed = new URL(String(url));
    if (
      opts.tokenStatus &&
      opts.tokenStatus !== 200 &&
      parsed.hostname === 'login.microsoftonline.com'
    ) {
      return new Response('boom', { status: opts.tokenStatus });
    }
    if (parsed.hostname === 'login.microsoftonline.com') {
      return new Response(JSON.stringify({ access_token: 'eyJhbGciOiJSUzI1NiJ9.test' }), {
        status: 200,
      });
    }
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (parsed.hostname === 'management.azure.com') {
      const page = registryPage.n;
      const pages = opts.registries ?? [[]];
      const items = pages[page] ?? [];
      const more = page < pages.length - 1;
      const next =
        opts.registryNext?.[page] ??
        (more
          ? `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.ContainerRegistry/registries?api-version=2023-07-01&$skiptoken=page-${page + 1}`
          : undefined);
      registryPage.n += 1;
      return new Response(JSON.stringify({ value: items, ...(next ? { nextLink: next } : {}) }), {
        status: 200,
      });
    }
    if (parsed.pathname === '/oauth2/exchange') {
      return new Response(JSON.stringify({ refresh_token: 'acr-refresh' }), { status: 200 });
    }
    if (parsed.pathname === '/oauth2/token') {
      return new Response(JSON.stringify({ access_token: 'acr-access' }), { status: 200 });
    }
    if (parsed.pathname === '/acr/v1/_catalog') {
      if (opts.catalogStatus && opts.catalogStatus !== 200) {
        return new Response('boom', { status: opts.catalogStatus });
      }
      const page = catalogPage.n;
      const pages = opts.catalog ?? [[]];
      const items = pages[page] ?? [];
      const more = page < pages.length - 1;
      const next =
        opts.catalogNext?.[page] ??
        (more ? `/acr/v1/_catalog?last=c-${page + 1}&n=100` : undefined);
      catalogPage.n += 1;
      const headers = new Headers({ 'content-type': 'application/json' });
      if (next) headers.set('link', `<${next}>; rel="next"`);
      return new Response(JSON.stringify({ repositories: items }), { status: 200, headers });
    }
    if (parsed.pathname.includes('/_manifests')) {
      if (opts.manifestStatus && opts.manifestStatus !== 200) {
        return new Response('boom', { status: opts.manifestStatus });
      }
      const parts = parsed.pathname.split('/').filter(Boolean);
      // /acr/v1/{repo...}/_manifests
      const repo = parts
        .slice(2, -1)
        .map((p) => decodeURIComponent(p))
        .join('/');
      const page = manifestPage[repo] ?? 0;
      const pages = opts.manifests?.[repo] ?? [[]];
      const items = pages[page] ?? [];
      const more = page < pages.length - 1;
      const next =
        opts.manifestNext?.[repo]?.[page] ??
        (more ? `/acr/v1/${repo}/_manifests?last=m-${page + 1}&n=100` : undefined);
      manifestPage[repo] = page + 1;
      const headers = new Headers({ 'content-type': 'application/json' });
      if (next) headers.set('link', `<${next}>; rel="next"`);
      return new Response(JSON.stringify({ manifests: items }), { status: 200, headers });
    }
    return new Response('unexpected', { status: 500 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function setAzureCreds(): void {
  process.env.AZURE_TENANT_ID = TENANT;
  process.env.AZURE_CLIENT_ID = CLIENT;
  process.env.AZURE_CLIENT_SECRET = 'super-secret';
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.AZURE_TENANT_ID;
  delete process.env.AZURE_CLIENT_ID;
  delete process.env.AZURE_CLIENT_SECRET;
  delete process.env.GITHUB_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
});

describe('imageToAsset / imageDigest / parseManifests', () => {
  it('maps identity as container_image keyed by digest, not tag', () => {
    const img: AcrImage = {
      subscriptionId: SUB,
      resourceGroup: RG,
      registry: REGISTRY,
      loginServer: LOGIN,
      repository: 'payments-api',
      digest: DIGEST_A,
      tags: ['latest', 'v1'],
    };
    expect(imageToAsset(img)).toMatchObject({
      kind: 'container_image',
      externalKey: `acr:${SUB}/${RG}/${REGISTRY}/payments-api@${DIGEST_A}`,
      name: `${REGISTRY}/payments-api`,
      source: 'acr',
      exposure: 'internal',
      attributes: {
        digest: DIGEST_A,
        tags: ['latest', 'v1'],
        repository: 'payments-api',
        registry: REGISTRY,
        resourceGroup: RG,
        subscriptionId: SUB,
        loginServer: LOGIN,
      },
    });
    expect(imageDigest(DIGEST_A)).toBe(DIGEST_A);
    expect(imageDigest('latest')).toBeUndefined();
    expect(imageDigest('v1.2.3')).toBeUndefined();
  });

  it('does not treat a tag as a digest identity', () => {
    expect(parseManifests({ manifests: [{ digest: 'latest', tags: ['latest'] }] })).toEqual([]);
    expect(parseManifests({ manifests: [{ digest: DIGEST_A, tags: ['latest'] }] })).toEqual([
      { digest: DIGEST_A, tags: ['latest'] },
    ]);
  });
});

describe('AcrConnector.discover', () => {
  it('inventories registries as digest-keyed container_image assets on ARM + azurecr.io', async () => {
    setAzureCreds();
    const fetchFn = stubAcr({
      registries: [[armRegistry(REGISTRY)]],
      catalog: [['payments-api', 'worker']],
      manifests: {
        'payments-api': [[manifest(DIGEST_A, ['latest', 'v1'])]],
        worker: [[manifest(DIGEST_B, ['stable'])]],
      },
    });
    const assets = (await collect(new AcrConnector().discover(ctx()))) as Array<{
      kind: string;
      source: string;
      externalKey: string;
      attributes: { tags: string[]; digest: string };
    }>;
    expect(assets.every((a) => a.kind === 'container_image')).toBe(true);
    expect(assets.every((a) => a.source === 'acr')).toBe(true);
    expect(assets.map((a) => a.externalKey)).toEqual([
      `acr:${SUB}/${RG}/${REGISTRY}/payments-api@${DIGEST_A}`,
      `acr:${SUB}/${RG}/${REGISTRY}/worker@${DIGEST_B}`,
    ]);
    expect(assets[0]?.attributes.tags).toEqual(['latest', 'v1']);
    expect(assets.every((a) => a.kind !== 'repository')).toBe(true);

    const hosts = fetchFn.mock.calls.map(([url]) => new URL(String(url)).hostname);
    expect(hosts).toContain('login.microsoftonline.com');
    expect(hosts).toContain('management.azure.com');
    expect(hosts).toContain(LOGIN);
    for (const [url] of fetchFn.mock.calls) {
      const parsed = new URL(String(url));
      expect(parsed.protocol).toBe('https:');
      expect(
        ['login.microsoftonline.com', 'management.azure.com', LOGIN].includes(parsed.hostname),
      ).toBe(true);
      expect(parsed.pathname).not.toMatch(/\/blobs?\//);
      expect(parsed.pathname).not.toMatch(/\/v2\//);
    }
    const tokenBodies = fetchFn.mock.calls
      .filter(([url]) => new URL(String(url)).hostname === 'login.microsoftonline.com')
      .map(([, init]) => String((init as RequestInit | undefined)?.body ?? ''));
    expect(
      tokenBodies.some((b) =>
        b.includes(encodeURIComponent('https://management.azure.com/.default')),
      ),
    ).toBe(true);
    expect(
      tokenBodies.some((b) =>
        b.includes(encodeURIComponent('https://containerregistry.azure.net/.default')),
      ),
    ).toBe(true);
    expect(
      fetchFn.mock.calls.some(([url]) =>
        String(url).startsWith(
          `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.ContainerRegistry/registries`,
        ),
      ),
    ).toBe(true);
    expect(
      fetchFn.mock.calls.some(([url]) =>
        String(url).startsWith(`https://${LOGIN}/acr/v1/_catalog`),
      ),
    ).toBe(true);
  });

  it('keeps one asset when the same digest is retagged', async () => {
    setAzureCreds();
    stubAcr({
      registries: [[armRegistry(REGISTRY)]],
      catalog: [['payments-api']],
      manifests: {
        'payments-api': [[manifest(DIGEST_A, ['latest']), manifest(DIGEST_A, ['v2'])]],
      },
    });
    const assets = (await collect(new AcrConnector().discover(ctx()))) as Array<{
      externalKey: string;
    }>;
    expect(assets).toHaveLength(1);
    expect(assets[0]?.externalKey).toBe(`acr:${SUB}/${RG}/${REGISTRY}/payments-api@${DIGEST_A}`);
  });

  it('does not invent a container_image from tags alone', async () => {
    setAzureCreds();
    stubAcr({
      registries: [[armRegistry(REGISTRY)]],
      catalog: [['payments-api']],
      manifests: { 'payments-api': [[{ digest: 'latest', tags: ['latest'] }]] },
    });
    const assets = await collect(new AcrConnector().discover(ctx()));
    expect(assets).toHaveLength(0);
  });

  it('honors the registries and repositories allowlists', async () => {
    setAzureCreds();
    stubAcr({
      registries: [[armRegistry(REGISTRY), armRegistry('other1')]],
      catalog: [['payments-api', 'other'], ['skip-me']],
      manifests: {
        'payments-api': [[manifest(DIGEST_A)]],
        other: [[manifest(DIGEST_B)]],
        'skip-me': [[manifest(DIGEST_B)]],
      },
    });
    const assets = (await collect(
      new AcrConnector().discover(
        ctx({ subscriptionId: SUB, registry: REGISTRY, repositories: ['payments-api'] }),
      ),
    )) as Array<{ externalKey: string }>;
    expect(assets.map((a) => a.externalKey)).toEqual([
      `acr:${SUB}/${RG}/${REGISTRY}/payments-api@${DIGEST_A}`,
    ]);
  });

  it('lists a resource-group-scoped ARM URL when resourceGroup is set', async () => {
    setAzureCreds();
    const fetchFn = stubAcr({
      registries: [[armRegistry(REGISTRY)]],
      catalog: [['payments-api']],
      manifests: { 'payments-api': [[manifest(DIGEST_A)]] },
    });
    await collect(new AcrConnector().discover(ctx({ subscriptionId: SUB, resourceGroup: RG })));
    expect(
      fetchFn.mock.calls.some(([url]) =>
        String(url).startsWith(
          `https://management.azure.com/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.ContainerRegistry/registries`,
        ),
      ),
    ).toBe(true);
  });

  it('requires a subscriptionId', async () => {
    setAzureCreds();
    await expect(collect(new AcrConnector().discover(ctx({})))).rejects.toThrow(/subscriptionId/);
  });

  it('succeeds on a last page of ACR_PER_PAGE with no next Link', async () => {
    setAzureCreds();
    const names = Array.from({ length: ACR_PER_PAGE }, (_, i) => `img-${i}`);
    const digestFor = (i: number) =>
      `sha256:${i.toString(16).padStart(2, '0')}${'a'.repeat(62)}` as const;
    const fetchFn = stubAcr({
      registries: [[armRegistry(REGISTRY)]],
      catalog: [names],
      manifests: Object.fromEntries(names.map((name, i) => [name, [[manifest(digestFor(i))]]])),
    });
    const assets = await collect(new AcrConnector().discover(ctx()));
    expect(assets).toHaveLength(ACR_PER_PAGE);
    const catalogCalls = fetchFn.mock.calls.filter(([url]) =>
      String(url).includes('/acr/v1/_catalog'),
    );
    expect(catalogCalls).toHaveLength(1);
  });

  it('fails when a catalog listing is truncated at the page cap', async () => {
    setAzureCreds();
    const pages = Array.from({ length: ACR_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: ACR_PER_PAGE }, (_, i) => `img-${p}-${i}`),
    );
    const fetchFn = stubAcr({
      registries: [[armRegistry(REGISTRY)]],
      catalog: pages,
      manifests: {},
    });
    await expect(collect(new AcrConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const catalogCalls = fetchFn.mock.calls.filter(([url]) =>
      String(url).includes('/acr/v1/_catalog'),
    );
    expect(catalogCalls).toHaveLength(ACR_MAX_PAGES);
  });

  it('fails when a manifest listing is truncated at the page cap', async () => {
    setAzureCreds();
    const pages = Array.from({ length: ACR_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: ACR_PER_PAGE }, (_, i) => {
        const hex = `${p.toString(16).padStart(2, '0')}${i.toString(16).padStart(2, '0')}${'b'.repeat(60)}`;
        return manifest(`sha256:${hex}`);
      }),
    );
    const fetchFn = stubAcr({
      registries: [[armRegistry(REGISTRY)]],
      catalog: [['payments-api']],
      manifests: { 'payments-api': pages },
    });
    await expect(collect(new AcrConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const manifestCalls = fetchFn.mock.calls.filter(([url]) => String(url).includes('/_manifests'));
    expect(manifestCalls).toHaveLength(ACR_MAX_PAGES);
  });

  it('fails when an ARM registry listing is truncated at the page cap', async () => {
    setAzureCreds();
    const pages = Array.from({ length: ACR_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: ACR_PER_PAGE }, (_, i) =>
        armRegistry(`reg${`${p}${i}`.padStart(4, '0')}`),
      ),
    );
    const fetchFn = stubAcr({ registries: pages, catalog: [[]], manifests: {} });
    await expect(collect(new AcrConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const armCalls = fetchFn.mock.calls.filter(
      ([url]) => new URL(String(url)).hostname === 'management.azure.com',
    );
    expect(armCalls).toHaveLength(ACR_MAX_PAGES);
  });

  it('fails closed when AZURE_* credentials are missing', async () => {
    const fetchFn = stubAcr({ registries: [[armRegistry(REGISTRY)]] });
    await expect(collect(new AcrConnector().discover(ctx()))).rejects.toThrow(/cannot be used/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when credentialRef is unset — no unauthenticated listing', async () => {
    setAzureCreds();
    const fetchFn = stubAcr({ registries: [[armRegistry(REGISTRY)]] });
    await expect(
      collect(new AcrConnector().discover(ctx({ subscriptionId: SUB }, null))),
    ).rejects.toThrow(/env:AZURE_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses env:GITHUB_* even when Azure secrets are present', async () => {
    setAzureCreds();
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchFn = stubAcr({ registries: [[armRegistry(REGISTRY)]] });
    await expect(
      collect(new AcrConnector().discover(ctx({ subscriptionId: SUB }, 'env:GITHUB_TOKEN'))),
    ).rejects.toThrow(/env:AZURE_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses a tenant-writable endpoint and never sends keys there', async () => {
    setAzureCreds();
    const fetchFn = stubAcr({ registries: [[armRegistry(REGISTRY)]] });
    await expect(
      collect(
        new AcrConnector().discover(
          ctx({
            subscriptionId: SUB,
            endpoint: 'https://evil.example',
            apiUrl: 'https://evil.example/arm',
            loginServer: 'acmeprod.azurecr.io',
            registryUrl: 'https://acmeprod.azurecr.io',
            acrUrl: 'https://acmeprod.azurecr.io/v2/',
            baseUrl: 'https://management.azure.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable ACR endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('does not take a tenant-supplied host even when mixed with a valid subscriptionId', async () => {
    setAzureCreds();
    const fetchFn = stubAcr({ registries: [[armRegistry(REGISTRY)]] });
    await expect(
      collect(
        new AcrConnector().discover(
          ctx({
            subscriptionId: SUB,
            host: 'acmeprod.azurecr.io',
            customEndpoint: 'https://acmeprod.azurecr.io.evil.example',
            authority: 'https://login.microsoftonline.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable ACR endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('requires a valid Azure subscription identifier', async () => {
    setAzureCreds();
    await expect(
      collect(new AcrConnector().discover(ctx({ subscriptionId: 'acme-prod.evil.example' }))),
    ).rejects.toThrow(/subscriptionId|subscription identifier|tenant-writable/);
  });

  it("refuses an ARM loginServer that is not the registry's own azurecr.io host", async () => {
    setAzureCreds();
    const fetchFn = stubAcr({
      registries: [[armRegistry(REGISTRY, 'acmeprod.azurecr.io.evil.example')]],
    });
    await expect(collect(new AcrConnector().discover(ctx()))).rejects.toThrow(
      /ARM-derived acmeprod\.azurecr\.io/,
    );
    for (const [url] of fetchFn.mock.calls) {
      expect(String(url)).not.toContain('evil.example');
      expect(new URL(String(url)).hostname).not.toBe(LOGIN);
    }
  });

  it('refuses an off-allowlist ACR Link and never sends the bearer there', async () => {
    setAzureCreds();
    const fetchFn = stubAcr({
      registries: [[armRegistry(REGISTRY)]],
      catalog: [['payments-api']],
      catalogNext: ['https://evil.example/acr?last=exfil'],
    });
    await expect(collect(new AcrConnector().discover(ctx()))).rejects.toThrow(
      /ARM-derived acmeprod\.azurecr\.io/,
    );
    for (const [url] of fetchFn.mock.calls) {
      expect(String(url)).not.toContain('evil.example');
    }
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    setAzureCreds();
    stubAcr({ status: 403 });
    await expect(collect(new AcrConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('fails closed when manifest listing is incomplete after catalog succeeded', async () => {
    setAzureCreds();
    stubAcr({
      registries: [[armRegistry(REGISTRY)]],
      catalog: [['payments-api']],
      manifests: { 'payments-api': [[manifest(DIGEST_A)]] },
      manifestStatus: 403,
    });
    await expect(collect(new AcrConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(
      collect(new AcrConnector().discover(ctx({ subscriptionId: SUB }, 'vault:azure'))),
    ).rejects.toThrow(/Unsupported credentialRef scheme/);
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret', async () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    await expect(
      collect(new AcrConnector().discover(ctx({ subscriptionId: SUB }, 'env:DATABASE_URL'))),
    ).rejects.toThrow(/not allowlisted/);
  });

  it('does not contain layer/blob download in the connector source', () => {
    const src = readFileSync(join(__dirname, 'acr.connector.ts'), 'utf8');
    expect(src).not.toMatch(/\/blobs\//);
    expect(src).not.toMatch(/\/v2\//);
    expect(src).not.toMatch(/application\/vnd\.oci/);
    expect(src).not.toMatch(/scanner-container-iac/);
    expect(src).not.toMatch(/\bdocker\b/);
    expect(src).toMatch(/acr\/v1|_catalog|_manifests|allowlistedAcrDataUrl/);
  });
});

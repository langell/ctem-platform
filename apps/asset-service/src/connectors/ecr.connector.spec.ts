import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  ECR_MAX_PAGES,
  ECR_PER_PAGE,
  EcrConnector,
  imageDigest,
  imageToAsset,
  parseImages,
  type EcrImage,
} from './ecr.connector';
import type { DiscoveryContext } from './connector.registry';

const ACCOUNT = '123456789012';
const REGION = 'us-east-1';
const DIGEST_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

const ctx = (
  config: Record<string, unknown> = { region: REGION },
  credentialRef: string | null = 'env:AWS_ACCESS_KEY_ID',
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

function callerXml(account = ACCOUNT): string {
  return `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>${account}</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`;
}

function repo(name: string, over: Record<string, unknown> = {}): object {
  return {
    repositoryName: name,
    registryId: ACCOUNT,
    repositoryArn: `arn:aws:ecr:${REGION}:${ACCOUNT}:repository/${name}`,
    repositoryUri: `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/${name}`,
    ...over,
  };
}

function image(digest: string, tags: string[] = ['latest']): object {
  return {
    imageDigest: digest,
    imageTags: tags,
    imageSizeInBytes: 1024,
    registryId: ACCOUNT,
  };
}

function ecrTarget(init?: RequestInit): string {
  const headers = (init?.headers ?? {}) as Record<string, string>;
  return headers['x-amz-target'] ?? headers['X-Amz-Target'] ?? '';
}

function stubEcr(opts: {
  repositories?: object[][];
  images?: Record<string, object[][]>;
  repoNext?: Array<string | undefined>;
  imageNext?: Record<string, Array<string | undefined>>;
  status?: number;
  imageStatus?: number;
}): ReturnType<typeof vi.fn> {
  const repoPage = { n: 0 };
  const imagePage: Record<string, number> = {};
  const fn = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const href = String(url);
    const body = String(init?.body ?? '');
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (href.includes('sts.') && body.includes('GetCallerIdentity')) {
      return new Response(callerXml(), { status: 200 });
    }
    const target = ecrTarget(init);
    if (target.endsWith('.DescribeRepositories')) {
      const page = repoPage.n;
      const pages = opts.repositories ?? [[]];
      const items = pages[page] ?? [];
      const more = page < pages.length - 1;
      const next = opts.repoNext?.[page] ?? (more ? `repo-${page + 1}` : undefined);
      repoPage.n += 1;
      return new Response(
        JSON.stringify({ repositories: items, ...(next ? { nextToken: next } : {}) }),
        { status: 200 },
      );
    }
    if (target.endsWith('.DescribeImages')) {
      if (opts.imageStatus && opts.imageStatus !== 200) {
        return new Response('boom', { status: opts.imageStatus });
      }
      const payload = JSON.parse(body) as { repositoryName?: string };
      const name = payload.repositoryName ?? '';
      const page = imagePage[name] ?? 0;
      const pages = opts.images?.[name] ?? [[]];
      const items = pages[page] ?? [];
      const more = page < pages.length - 1;
      const next = opts.imageNext?.[name]?.[page] ?? (more ? `img-${name}-${page + 1}` : undefined);
      imagePage[name] = page + 1;
      return new Response(
        JSON.stringify({ imageDetails: items, ...(next ? { nextToken: next } : {}) }),
        { status: 200 },
      );
    }
    return new Response('unexpected', { status: 500 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function setAwsCreds(): void {
  process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
  process.env.AWS_SECRET_ACCESS_KEY = 'secret';
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.AWS_SESSION_TOKEN;
  delete process.env.GITHUB_TOKEN;
});

describe('imageToAsset / imageDigest', () => {
  it('maps identity as container_image keyed by digest, not tag', () => {
    const img: EcrImage = {
      accountId: ACCOUNT,
      region: REGION,
      repositoryName: 'payments-api',
      digest: DIGEST_A,
      tags: ['latest', 'v1'],
    };
    expect(imageToAsset(img)).toMatchObject({
      kind: 'container_image',
      externalKey: `ecr:${ACCOUNT}/payments-api@${DIGEST_A}`,
      name: 'payments-api',
      source: 'ecr',
      exposure: 'internal',
      attributes: {
        digest: DIGEST_A,
        tags: ['latest', 'v1'],
        repository: 'payments-api',
        region: REGION,
      },
    });
    expect(imageDigest(DIGEST_A)).toBe(DIGEST_A);
    expect(imageDigest('latest')).toBeUndefined();
    expect(imageDigest('v1.2.3')).toBeUndefined();
  });

  it('does not treat a tag as a digest identity', () => {
    expect(
      parseImages({ imageDetails: [{ imageDigest: 'latest', imageTags: ['latest'] }] }),
    ).toEqual([]);
    expect(
      parseImages({ imageDetails: [{ imageDigest: DIGEST_A, imageTags: ['latest'] }] }),
    ).toEqual([{ digest: DIGEST_A, tags: ['latest'] }]);
  });
});

describe('EcrConnector.discover', () => {
  it('inventories repositories as digest-keyed container_image assets on api.ecr', async () => {
    setAwsCreds();
    const fetchFn = stubEcr({
      repositories: [[repo('payments-api'), repo('worker')]],
      images: {
        'payments-api': [[image(DIGEST_A, ['latest', 'v1'])]],
        worker: [[image(DIGEST_B, ['stable'])]],
      },
    });
    const assets = (await collect(new EcrConnector().discover(ctx()))) as Array<{
      kind: string;
      source: string;
      externalKey: string;
      attributes: { tags: string[]; digest: string };
    }>;
    expect(assets.every((a) => a.kind === 'container_image')).toBe(true);
    expect(assets.every((a) => a.source === 'ecr')).toBe(true);
    expect(assets.map((a) => a.externalKey)).toEqual([
      `ecr:${ACCOUNT}/payments-api@${DIGEST_A}`,
      `ecr:${ACCOUNT}/worker@${DIGEST_B}`,
    ]);
    expect(assets[0]?.attributes.tags).toEqual(['latest', 'v1']);
    expect(assets.every((a) => a.kind !== 'repository')).toBe(true);

    for (const [url] of fetchFn.mock.calls) {
      const parsed = new URL(String(url));
      expect(parsed.protocol).toBe('https:');
      expect(parsed.hostname.endsWith('amazonaws.com')).toBe(true);
      expect(parsed.hostname).not.toContain('dkr.ecr');
      expect(parsed.pathname).not.toMatch(/\/blobs?\//);
      expect(parsed.pathname).not.toMatch(/\/v2\//);
      expect(parsed.pathname).not.toMatch(/\/manifests\//);
    }
    expect(
      fetchFn.mock.calls.some(([url]) => String(url).includes('sts.us-east-1.amazonaws.com')),
    ).toBe(true);
    expect(
      fetchFn.mock.calls.some(
        ([url]) => String(url) === 'https://api.ecr.us-east-1.amazonaws.com/',
      ),
    ).toBe(true);
  });

  it('lists each configured region against api.ecr.{region}.amazonaws.com', async () => {
    setAwsCreds();
    const fetchFn = stubEcr({
      repositories: [[repo('payments-api')], [repo('payments-api')]],
      images: { 'payments-api': [[image(DIGEST_A)], [image(DIGEST_B)]] },
    });
    const assets = (await collect(
      new EcrConnector().discover(ctx({ region: 'us-east-1', regions: ['eu-west-1'] })),
    )) as Array<{ externalKey: string; attributes: { region: string } }>;
    expect(assets.map((a) => a.externalKey)).toEqual([
      `ecr:${ACCOUNT}/payments-api@${DIGEST_A}`,
      `ecr:${ACCOUNT}/payments-api@${DIGEST_B}`,
    ]);
    const ecrHosts = fetchFn.mock.calls
      .map(([url]) => new URL(String(url)).hostname)
      .filter((h) => h.startsWith('api.ecr.'));
    expect(ecrHosts).toEqual(
      expect.arrayContaining([
        'api.ecr.us-east-1.amazonaws.com',
        'api.ecr.eu-west-1.amazonaws.com',
      ]),
    );
  });

  it('keeps one asset when the same digest is retagged', async () => {
    setAwsCreds();
    stubEcr({
      repositories: [[repo('payments-api')]],
      images: {
        'payments-api': [[image(DIGEST_A, ['latest']), image(DIGEST_A, ['v2'])]],
      },
    });
    const assets = (await collect(new EcrConnector().discover(ctx()))) as Array<{
      externalKey: string;
    }>;
    expect(assets).toHaveLength(1);
    expect(assets[0]?.externalKey).toBe(`ecr:${ACCOUNT}/payments-api@${DIGEST_A}`);
  });

  it('does not invent a container_image from tags alone', async () => {
    setAwsCreds();
    stubEcr({
      repositories: [[repo('payments-api')]],
      images: {
        'payments-api': [[{ imageDigest: 'latest', imageTags: ['latest'] }]],
      },
    });
    const assets = await collect(new EcrConnector().discover(ctx()));
    expect(assets).toHaveLength(0);
  });

  it('honors the repositories allowlist', async () => {
    setAwsCreds();
    stubEcr({
      repositories: [[repo('payments-api'), repo('other')]],
      images: {
        'payments-api': [[image(DIGEST_A)]],
        other: [[image(DIGEST_B)]],
      },
    });
    const assets = (await collect(
      new EcrConnector().discover(ctx({ region: REGION, repositories: ['payments-api'] })),
    )) as Array<{ externalKey: string }>;
    expect(assets.map((a) => a.externalKey)).toEqual([`ecr:${ACCOUNT}/payments-api@${DIGEST_A}`]);
  });

  it('requires a region or regions', async () => {
    setAwsCreds();
    await expect(collect(new EcrConnector().discover(ctx({})))).rejects.toThrow(/region/);
  });

  it('succeeds on a last page of ECR_PER_PAGE with no nextToken', async () => {
    setAwsCreds();
    const names = Array.from({ length: ECR_PER_PAGE }, (_, i) => `img-${i}`);
    const digestFor = (i: number) =>
      `sha256:${i.toString(16).padStart(2, '0')}${'a'.repeat(62)}` as const;
    const fetchFn = stubEcr({
      repositories: [names.map((name) => repo(name))],
      images: Object.fromEntries(names.map((name, i) => [name, [[image(digestFor(i))]]])),
    });
    const assets = await collect(new EcrConnector().discover(ctx()));
    expect(assets).toHaveLength(ECR_PER_PAGE);
    const repoCalls = fetchFn.mock.calls.filter(([, init]) =>
      ecrTarget(init as RequestInit).endsWith('.DescribeRepositories'),
    );
    expect(repoCalls).toHaveLength(1);
  });

  it('fails when a repository listing is truncated at the page cap', async () => {
    setAwsCreds();
    const pages = Array.from({ length: ECR_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: ECR_PER_PAGE }, (_, i) => repo(`img-${p}-${i}`)),
    );
    const fetchFn = stubEcr({ repositories: pages, images: {} });
    await expect(collect(new EcrConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const repoCalls = fetchFn.mock.calls.filter(([, init]) =>
      ecrTarget(init as RequestInit).endsWith('.DescribeRepositories'),
    );
    expect(repoCalls).toHaveLength(ECR_MAX_PAGES);
  });

  it('fails when an image listing is truncated at the page cap', async () => {
    setAwsCreds();
    const pages = Array.from({ length: ECR_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: ECR_PER_PAGE }, (_, i) => {
        const hex = `${p.toString(16).padStart(2, '0')}${i.toString(16).padStart(2, '0')}${'b'.repeat(60)}`;
        return image(`sha256:${hex}`);
      }),
    );
    const fetchFn = stubEcr({
      repositories: [[repo('payments-api')]],
      images: { 'payments-api': pages },
    });
    await expect(collect(new EcrConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const imageCalls = fetchFn.mock.calls.filter(([, init]) =>
      ecrTarget(init as RequestInit).endsWith('.DescribeImages'),
    );
    expect(imageCalls).toHaveLength(ECR_MAX_PAGES);
  });

  it('fails closed when AWS_* credentials are missing', async () => {
    const fetchFn = stubEcr({ repositories: [[repo('payments-api')]] });
    await expect(collect(new EcrConnector().discover(ctx()))).rejects.toThrow(/cannot be used/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when credentialRef is unset — no unauthenticated listing', async () => {
    setAwsCreds();
    const fetchFn = stubEcr({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(new EcrConnector().discover(ctx({ region: REGION }, null))),
    ).rejects.toThrow(/env:AWS_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses env:GITHUB_* even when AWS keys are present', async () => {
    setAwsCreds();
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchFn = stubEcr({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(new EcrConnector().discover(ctx({ region: REGION }, 'env:GITHUB_TOKEN'))),
    ).rejects.toThrow(/env:AWS_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses a tenant-writable endpoint and never sends keys there', async () => {
    setAwsCreds();
    const fetchFn = stubEcr({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(
        new EcrConnector().discover(
          ctx({
            region: REGION,
            endpoint: 'https://evil.example',
            apiUrl: 'https://evil.example/aws',
            registryUrl: 'https://123.dkr.ecr.us-east-1.amazonaws.com',
            ecrUrl: 'https://api.ecr.us-east-1.amazonaws.com',
            baseUrl: 'https://api.ecr.us-east-1.amazonaws.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable ECR endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('does not take a tenant-supplied host even when mixed with a valid region', async () => {
    setAwsCreds();
    const fetchFn = stubEcr({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(
        new EcrConnector().discover(
          ctx({
            region: REGION,
            host: '123456789012.dkr.ecr.us-east-1.amazonaws.com',
            customEndpoint: 'https://api.ecr.us-east-1.amazonaws.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable ECR endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('requires a valid AWS region identifier', async () => {
    setAwsCreds();
    await expect(
      collect(new EcrConnector().discover(ctx({ region: 'us-east-1.evil.example' }))),
    ).rejects.toThrow(/region/);
  });

  it('fails closed when the configured accountId does not match the caller', async () => {
    setAwsCreds();
    const fetchFn = stubEcr({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(new EcrConnector().discover(ctx({ region: REGION, accountId: '999999999999' }))),
    ).rejects.toThrow(/does not match configured accountId/);
    const ecrCalls = fetchFn.mock.calls.filter(([url]) => String(url).includes('api.ecr.'));
    expect(ecrCalls).toHaveLength(0);
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    setAwsCreds();
    stubEcr({ status: 403 });
    await expect(collect(new EcrConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('fails closed when image listing is incomplete after repositories succeeded', async () => {
    setAwsCreds();
    stubEcr({
      repositories: [[repo('payments-api')]],
      images: { 'payments-api': [[image(DIGEST_A)]] },
      imageStatus: 403,
    });
    await expect(collect(new EcrConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(
      collect(new EcrConnector().discover(ctx({ region: REGION }, 'vault:aws'))),
    ).rejects.toThrow(/Unsupported credentialRef scheme/);
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret', async () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    await expect(
      collect(new EcrConnector().discover(ctx({ region: REGION }, 'env:DATABASE_URL'))),
    ).rejects.toThrow(/not allowlisted/);
  });

  it('does not contain layer/blob download in the connector source', () => {
    const src = readFileSync(join(__dirname, 'ecr.connector.ts'), 'utf8');
    expect(src).not.toMatch(/dkr\.ecr/);
    expect(src).not.toMatch(/\/blobs\//);
    expect(src).not.toMatch(/\/manifests\//);
    expect(src).not.toMatch(/application\/vnd\.oci/);
    expect(src).toMatch(/api\.ecr|allowlistedEcrApiUrl|ecrApiUrl/);
  });
});

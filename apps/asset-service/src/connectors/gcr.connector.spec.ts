import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  GCR_MAX_PAGES,
  GCR_PER_PAGE,
  GcrConnector,
  imageDigest,
  imageToAsset,
  parseDockerImageName,
  parseDockerImages,
  type GcrImage,
} from './gcr.connector';
import type { DiscoveryContext } from './connector.registry';

const PROJECT = 'acme-prod';
const LOCATION = 'us-central1';
const DIGEST_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const gcpPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

const ctx = (
  config: Record<string, unknown> = { projectId: PROJECT },
  credentialRef: string | null = 'env:GCP_CLIENT_EMAIL',
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

function repo(name: string, location = LOCATION, over: Record<string, unknown> = {}): object {
  return {
    name: `projects/${PROJECT}/locations/${location}/repositories/${name}`,
    format: 'DOCKER',
    ...over,
  };
}

function dockerImage(
  repository: string,
  image: string,
  digest: string,
  tags: string[] = ['latest'],
  location = LOCATION,
): object {
  const encodedImage = encodeURIComponent(image);
  return {
    name: `projects/${PROJECT}/locations/${location}/repositories/${repository}/dockerImages/${encodedImage}@${digest}`,
    uri: `${location}-docker.pkg.dev/${PROJECT}/${repository}/${image}@${digest}`,
    tags,
    imageSizeBytes: '1024',
  };
}

function stubGcr(opts: {
  repositories?: object[][];
  images?: Record<string, object[][]>;
  repoNext?: Array<string | undefined>;
  imageNext?: Record<string, Array<string | undefined>>;
  status?: number;
  imageStatus?: number;
  tokenStatus?: number;
}): ReturnType<typeof vi.fn> {
  const repoPage = { n: 0 };
  const imagePage: Record<string, number> = {};
  const fn = vi.fn(async (url: string | URL, _init?: RequestInit) => {
    const parsed = new URL(String(url));
    if (
      opts.tokenStatus &&
      opts.tokenStatus !== 200 &&
      parsed.hostname === 'oauth2.googleapis.com'
    ) {
      return new Response('boom', { status: opts.tokenStatus });
    }
    if (parsed.hostname === 'oauth2.googleapis.com') {
      return new Response(JSON.stringify({ access_token: 'ya29.test' }), { status: 200 });
    }
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (parsed.pathname.includes('/dockerImages')) {
      if (opts.imageStatus && opts.imageStatus !== 200) {
        return new Response('boom', { status: opts.imageStatus });
      }
      const parts = parsed.pathname.split('/');
      const repoIdx = parts.indexOf('repositories');
      const name = decodeURIComponent(parts[repoIdx + 1] ?? '');
      const page = imagePage[name] ?? 0;
      const pages = opts.images?.[name] ?? [[]];
      const items = pages[page] ?? [];
      const more = page < pages.length - 1;
      const next = opts.imageNext?.[name]?.[page] ?? (more ? `img-${name}-${page + 1}` : undefined);
      imagePage[name] = page + 1;
      return new Response(
        JSON.stringify({ dockerImages: items, ...(next ? { nextPageToken: next } : {}) }),
        { status: 200 },
      );
    }
    if (parsed.pathname.endsWith('/repositories') || parsed.pathname.includes('/repositories')) {
      const page = repoPage.n;
      const pages = opts.repositories ?? [[]];
      const items = pages[page] ?? [];
      const more = page < pages.length - 1;
      const next = opts.repoNext?.[page] ?? (more ? `repo-${page + 1}` : undefined);
      repoPage.n += 1;
      return new Response(
        JSON.stringify({ repositories: items, ...(next ? { nextPageToken: next } : {}) }),
        { status: 200 },
      );
    }
    return new Response('unexpected', { status: 500 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function setGcpCreds(): void {
  process.env.GCP_CLIENT_EMAIL = 'ctem-discovery@acme-prod.iam.gserviceaccount.com';
  process.env.GCP_PRIVATE_KEY = gcpPem;
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.GCP_CLIENT_EMAIL;
  delete process.env.GCP_PRIVATE_KEY;
  delete process.env.AWS_ACCESS_KEY_ID;
});

describe('imageToAsset / imageDigest / parseDockerImageName', () => {
  it('maps identity as container_image keyed by digest, not tag', () => {
    const img: GcrImage = {
      projectId: PROJECT,
      location: LOCATION,
      repository: 'payments-api',
      image: 'web',
      digest: DIGEST_A,
      tags: ['latest', 'v1'],
    };
    expect(imageToAsset(img)).toMatchObject({
      kind: 'container_image',
      externalKey: `gcr:${PROJECT}/${LOCATION}/payments-api/web@${DIGEST_A}`,
      name: 'payments-api/web',
      source: 'gcr',
      exposure: 'internal',
      attributes: {
        digest: DIGEST_A,
        tags: ['latest', 'v1'],
        repository: 'payments-api',
        location: LOCATION,
        projectId: PROJECT,
        image: 'web',
      },
    });
    expect(imageDigest(DIGEST_A)).toBe(DIGEST_A);
    expect(imageDigest('latest')).toBeUndefined();
    expect(imageDigest('v1.2.3')).toBeUndefined();
  });

  it('does not treat a tag as a digest identity', () => {
    expect(
      parseDockerImages({
        dockerImages: [
          {
            name: `projects/${PROJECT}/locations/${LOCATION}/repositories/payments/dockerImages/web@latest`,
            tags: ['latest'],
          },
        ],
      }),
    ).toEqual([]);
    expect(
      parseDockerImageName(
        `projects/${PROJECT}/locations/${LOCATION}/repositories/payments/dockerImages/web@${DIGEST_A}`,
      ),
    ).toEqual({
      projectId: PROJECT,
      location: LOCATION,
      repository: 'payments',
      image: 'web',
      digest: DIGEST_A,
    });
  });

  it('decodes nested image paths from the resource name', () => {
    expect(
      parseDockerImageName(
        `projects/${PROJECT}/locations/us/repositories/gcr.io/dockerImages/team%2Fapi@${DIGEST_A}`,
      ),
    ).toEqual({
      projectId: PROJECT,
      location: 'us',
      repository: 'gcr.io',
      image: 'team/api',
      digest: DIGEST_A,
    });
  });
});

describe('GcrConnector.discover', () => {
  it('inventories repositories as digest-keyed container_image assets on artifactregistry', async () => {
    setGcpCreds();
    const fetchFn = stubGcr({
      repositories: [[repo('payments-api'), repo('worker')]],
      images: {
        'payments-api': [[dockerImage('payments-api', 'web', DIGEST_A, ['latest', 'v1'])]],
        worker: [[dockerImage('worker', 'app', DIGEST_B, ['stable'])]],
      },
    });
    const assets = (await collect(new GcrConnector().discover(ctx()))) as Array<{
      kind: string;
      source: string;
      externalKey: string;
      attributes: { tags: string[]; digest: string };
    }>;
    expect(assets.every((a) => a.kind === 'container_image')).toBe(true);
    expect(assets.every((a) => a.source === 'gcr')).toBe(true);
    expect(assets.map((a) => a.externalKey)).toEqual([
      `gcr:${PROJECT}/${LOCATION}/payments-api/web@${DIGEST_A}`,
      `gcr:${PROJECT}/${LOCATION}/worker/app@${DIGEST_B}`,
    ]);
    expect(assets[0]?.attributes.tags).toEqual(['latest', 'v1']);
    expect(assets.every((a) => a.kind !== 'repository')).toBe(true);

    for (const [url] of fetchFn.mock.calls) {
      const parsed = new URL(String(url));
      expect(parsed.protocol).toBe('https:');
      expect(parsed.hostname.endsWith('googleapis.com')).toBe(true);
      expect(parsed.hostname).not.toBe('gcr.io');
      expect(parsed.hostname).not.toContain('pkg.dev');
      expect(parsed.pathname).not.toMatch(/\/blobs?\//);
      expect(parsed.pathname).not.toMatch(/\/v2\//);
      expect(parsed.pathname).not.toMatch(/\/manifests\//);
    }
    expect(String(fetchFn.mock.calls[0][0])).toBe('https://oauth2.googleapis.com/token');
    const tokenBody = String(fetchFn.mock.calls[0][1]?.body ?? '');
    expect(tokenBody).toContain('assertion=');
    const assertion = decodeURIComponent(tokenBody.split('assertion=')[1] ?? '');
    const payload = JSON.parse(
      Buffer.from(assertion.split('.')[1] ?? '', 'base64url').toString(),
    ) as { scope?: string; aud?: string };
    expect(payload.aud).toBe('https://oauth2.googleapis.com/token');
    expect(payload.scope).toBe('https://www.googleapis.com/auth/artifactregistry.readonly');
    expect(
      fetchFn.mock.calls.some(([url]) =>
        String(url).startsWith(
          `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/-/repositories`,
        ),
      ),
    ).toBe(true);
  });

  it('lists each configured location against artifactregistry.googleapis.com', async () => {
    setGcpCreds();
    const fetchFn = stubGcr({
      repositories: [[repo('payments-api', 'us-central1')], [repo('payments-api', 'europe-west1')]],
      images: {
        'payments-api': [
          [dockerImage('payments-api', 'web', DIGEST_A, ['latest'], 'us-central1')],
          [dockerImage('payments-api', 'web', DIGEST_B, ['latest'], 'europe-west1')],
        ],
      },
    });
    const assets = (await collect(
      new GcrConnector().discover(
        ctx({ projectId: PROJECT, location: 'us-central1', locations: ['europe-west1'] }),
      ),
    )) as Array<{ externalKey: string; attributes: { location: string } }>;
    expect(assets.map((a) => a.externalKey)).toEqual([
      `gcr:${PROJECT}/us-central1/payments-api/web@${DIGEST_A}`,
      `gcr:${PROJECT}/europe-west1/payments-api/web@${DIGEST_B}`,
    ]);
    const arPaths = fetchFn.mock.calls
      .map(([url]) => String(url))
      .filter((u) => u.includes('artifactregistry.googleapis.com') && u.includes('/repositories'));
    expect(arPaths.some((u) => u.includes('/locations/us-central1/'))).toBe(true);
    expect(arPaths.some((u) => u.includes('/locations/europe-west1/'))).toBe(true);
    expect(arPaths.some((u) => u.includes('/locations/-/'))).toBe(false);
  });

  it('keeps one asset when the same digest is retagged', async () => {
    setGcpCreds();
    stubGcr({
      repositories: [[repo('payments-api')]],
      images: {
        'payments-api': [
          [
            dockerImage('payments-api', 'web', DIGEST_A, ['latest']),
            dockerImage('payments-api', 'web', DIGEST_A, ['v2']),
          ],
        ],
      },
    });
    const assets = (await collect(new GcrConnector().discover(ctx()))) as Array<{
      externalKey: string;
    }>;
    expect(assets).toHaveLength(1);
    expect(assets[0]?.externalKey).toBe(`gcr:${PROJECT}/${LOCATION}/payments-api/web@${DIGEST_A}`);
  });

  it('does not invent a container_image from tags alone', async () => {
    setGcpCreds();
    stubGcr({
      repositories: [[repo('payments-api')]],
      images: {
        'payments-api': [
          [
            {
              name: `projects/${PROJECT}/locations/${LOCATION}/repositories/payments-api/dockerImages/web@latest`,
              tags: ['latest'],
            },
          ],
        ],
      },
    });
    const assets = await collect(new GcrConnector().discover(ctx()));
    expect(assets).toHaveLength(0);
  });

  it('honors the repositories allowlist and skips non-DOCKER formats', async () => {
    setGcpCreds();
    stubGcr({
      repositories: [
        [repo('payments-api'), repo('other'), repo('charts', LOCATION, { format: 'KFP' })],
      ],
      images: {
        'payments-api': [[dockerImage('payments-api', 'web', DIGEST_A)]],
        other: [[dockerImage('other', 'app', DIGEST_B)]],
        charts: [[dockerImage('charts', 'pkg', DIGEST_B)]],
      },
    });
    const assets = (await collect(
      new GcrConnector().discover(
        ctx({ projectId: PROJECT, repositories: ['payments-api', 'charts'] }),
      ),
    )) as Array<{ externalKey: string }>;
    expect(assets.map((a) => a.externalKey)).toEqual([
      `gcr:${PROJECT}/${LOCATION}/payments-api/web@${DIGEST_A}`,
    ]);
  });

  it('requires a projectId or project', async () => {
    setGcpCreds();
    await expect(collect(new GcrConnector().discover(ctx({})))).rejects.toThrow(
      /projectId|project/,
    );
  });

  it('accepts project as an alias of projectId', async () => {
    setGcpCreds();
    stubGcr({
      repositories: [[repo('payments-api')]],
      images: { 'payments-api': [[dockerImage('payments-api', 'web', DIGEST_A)]] },
    });
    const assets = (await collect(
      new GcrConnector().discover(ctx({ project: PROJECT })),
    )) as Array<{ externalKey: string }>;
    expect(assets.map((a) => a.externalKey)).toEqual([
      `gcr:${PROJECT}/${LOCATION}/payments-api/web@${DIGEST_A}`,
    ]);
  });

  it('succeeds on a last page of GCR_PER_PAGE with no nextPageToken', async () => {
    setGcpCreds();
    const names = Array.from({ length: GCR_PER_PAGE }, (_, i) => `img-${i}`);
    const digestFor = (i: number) =>
      `sha256:${i.toString(16).padStart(2, '0')}${'a'.repeat(62)}` as const;
    const fetchFn = stubGcr({
      repositories: [names.map((name) => repo(name))],
      images: Object.fromEntries(
        names.map((name, i) => [name, [[dockerImage(name, 'app', digestFor(i))]]]),
      ),
    });
    const assets = await collect(new GcrConnector().discover(ctx()));
    expect(assets).toHaveLength(GCR_PER_PAGE);
    const repoCalls = fetchFn.mock.calls.filter(([url]) => {
      const parsed = new URL(String(url));
      return (
        parsed.hostname === 'artifactregistry.googleapis.com' &&
        parsed.pathname.endsWith('/repositories')
      );
    });
    expect(repoCalls).toHaveLength(1);
  });

  it('fails when a repository listing is truncated at the page cap', async () => {
    setGcpCreds();
    const pages = Array.from({ length: GCR_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: GCR_PER_PAGE }, (_, i) => repo(`img-${p}-${i}`)),
    );
    const fetchFn = stubGcr({ repositories: pages, images: {} });
    await expect(collect(new GcrConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const repoCalls = fetchFn.mock.calls.filter(([url]) => {
      const parsed = new URL(String(url));
      return (
        parsed.hostname === 'artifactregistry.googleapis.com' &&
        parsed.pathname.endsWith('/repositories')
      );
    });
    expect(repoCalls).toHaveLength(GCR_MAX_PAGES);
  });

  it('fails when an image listing is truncated at the page cap', async () => {
    setGcpCreds();
    const pages = Array.from({ length: GCR_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: GCR_PER_PAGE }, (_, i) => {
        const hex = `${p.toString(16).padStart(2, '0')}${i.toString(16).padStart(2, '0')}${'b'.repeat(60)}`;
        return dockerImage('payments-api', `img-${p}-${i}`, `sha256:${hex}`);
      }),
    );
    const fetchFn = stubGcr({
      repositories: [[repo('payments-api')]],
      images: { 'payments-api': pages },
    });
    await expect(collect(new GcrConnector().discover(ctx()))).rejects.toThrow(/truncated/);
    const imageCalls = fetchFn.mock.calls.filter(([url]) => String(url).includes('/dockerImages'));
    expect(imageCalls).toHaveLength(GCR_MAX_PAGES);
  });

  it('fails closed when GCP_* credentials are missing', async () => {
    const fetchFn = stubGcr({ repositories: [[repo('payments-api')]] });
    await expect(collect(new GcrConnector().discover(ctx()))).rejects.toThrow(/cannot be used/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when credentialRef is unset — no unauthenticated listing', async () => {
    setGcpCreds();
    const fetchFn = stubGcr({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(new GcrConnector().discover(ctx({ projectId: PROJECT }, null))),
    ).rejects.toThrow(/env:GCP_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses env:AWS_* even when GCP keys are present', async () => {
    setGcpCreds();
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    const fetchFn = stubGcr({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(new GcrConnector().discover(ctx({ projectId: PROJECT }, 'env:AWS_ACCESS_KEY_ID'))),
    ).rejects.toThrow(/env:GCP_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses a tenant-writable endpoint and never sends keys there', async () => {
    setGcpCreds();
    const fetchFn = stubGcr({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(
        new GcrConnector().discover(
          ctx({
            projectId: PROJECT,
            endpoint: 'https://evil.example',
            apiUrl: 'https://evil.example/gcp',
            registryUrl: 'https://gcr.io',
            gcrUrl: 'https://us-docker.pkg.dev/acme-prod/app',
            baseUrl: 'https://artifactregistry.googleapis.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable GCR endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('does not take a tenant-supplied host even when mixed with a valid projectId', async () => {
    setGcpCreds();
    const fetchFn = stubGcr({ repositories: [[repo('payments-api')]] });
    await expect(
      collect(
        new GcrConnector().discover(
          ctx({
            projectId: PROJECT,
            host: 'gcr.io',
            customEndpoint: 'https://artifactregistry.googleapis.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable GCR endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('requires a valid GCP project identifier', async () => {
    setGcpCreds();
    await expect(
      collect(new GcrConnector().discover(ctx({ projectId: 'acme-prod.evil.example' }))),
    ).rejects.toThrow(/projectId|project identifier/);
  });

  it('requires a valid location identifier — not a registry host', async () => {
    setGcpCreds();
    await expect(
      collect(
        new GcrConnector().discover(ctx({ projectId: PROJECT, location: 'us-docker.pkg.dev' })),
      ),
    ).rejects.toThrow(/location/);
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    setGcpCreds();
    stubGcr({ status: 403 });
    await expect(collect(new GcrConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('fails closed when image listing is incomplete after repositories succeeded', async () => {
    setGcpCreds();
    stubGcr({
      repositories: [[repo('payments-api')]],
      images: { 'payments-api': [[dockerImage('payments-api', 'web', DIGEST_A)]] },
      imageStatus: 403,
    });
    await expect(collect(new GcrConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(
      collect(new GcrConnector().discover(ctx({ projectId: PROJECT }, 'vault:gcp'))),
    ).rejects.toThrow(/Unsupported credentialRef scheme/);
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret', async () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    await expect(
      collect(new GcrConnector().discover(ctx({ projectId: PROJECT }, 'env:DATABASE_URL'))),
    ).rejects.toThrow(/not allowlisted/);
  });

  it('does not contain layer/blob download in the connector source', () => {
    const src = readFileSync(join(__dirname, 'gcr.connector.ts'), 'utf8');
    expect(src).not.toMatch(/gcr\.io/);
    expect(src).not.toMatch(/pkg\.dev/);
    expect(src).not.toMatch(/\/blobs\//);
    expect(src).not.toMatch(/\/manifests\//);
    expect(src).not.toMatch(/application\/vnd\.oci/);
    expect(src).toMatch(
      /artifactregistry\.googleapis\.com|allowlistedGcrApiUrl|gcrDockerImagesUrl/,
    );
  });
});

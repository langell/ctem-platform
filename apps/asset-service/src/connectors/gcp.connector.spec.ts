import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  GCP_MAX_PAGES,
  GCP_PER_PAGE,
  GcpConnector,
  bucketToAsset,
  instanceToAsset,
  parseAggregatedInstances,
  type GcpInstance,
} from './gcp.connector';
import type { DiscoveryContext } from './connector.registry';

const PROJECT = 'acme-prod';
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

function instanceBody(names: string[], nextToken?: string): string {
  const instances = names.map(
    (name) => ({
      name,
      zone: `https://www.googleapis.com/compute/v1/projects/${PROJECT}/zones/us-central1-a`,
      status: 'RUNNING',
      networkInterfaces: [{ networkIP: '10.128.0.2' }],
    }),
  );
  return JSON.stringify({
    items: { 'zones/us-central1-a': { instances } },
    ...(nextToken ? { nextPageToken: nextToken } : {}),
  });
}

function bucketsBody(names: string[]): string {
  return JSON.stringify({ items: names.map((name) => ({ name, location: 'US' })) });
}

function stubGcp(opts: {
  instances?: string[][];
  buckets?: string[];
  status?: number;
  tokenStatus?: number;
}): ReturnType<typeof vi.fn> {
  let instancePage = 0;
  const fn = vi.fn(async (url: string | URL, _init?: RequestInit) => {
    const parsed = new URL(String(url));
    const href = parsed.href;
    if (opts.tokenStatus && opts.tokenStatus !== 200 && parsed.hostname === 'oauth2.googleapis.com') {
      return new Response('boom', { status: opts.tokenStatus });
    }
    if (parsed.hostname === 'oauth2.googleapis.com') {
      return new Response(JSON.stringify({ access_token: 'ya29.test' }), { status: 200 });
    }
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (href.includes('/aggregated/instances')) {
      const page = opts.instances?.[instancePage] ?? [];
      const more = opts.instances && instancePage < opts.instances.length - 1;
      instancePage += 1;
      return new Response(instanceBody(page, more ? `page-${instancePage}` : undefined), {
        status: 200,
      });
    }
    if (href.includes('/global/firewalls')) {
      return new Response(JSON.stringify({ items: [] }), { status: 200 });
    }
    if (href.includes('/aggregated/addresses')) {
      return new Response(JSON.stringify({ items: {} }), { status: 200 });
    }
    if (parsed.hostname === 'storage.googleapis.com') {
      return new Response(bucketsBody(opts.buckets ?? []), { status: 200 });
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
});

describe('instanceToAsset / bucketToAsset', () => {
  it('maps identity as cloud_resource', () => {
    const inst: GcpInstance = { name: 'web', zone: 'us-central1-a', natIp: '1.2.3.4' };
    expect(instanceToAsset(PROJECT, inst)).toMatchObject({
      kind: 'cloud_resource',
      externalKey: `gcp:${PROJECT}:gce:us-central1-a:web`,
      name: 'web',
      source: 'gcp',
      exposure: 'internet_facing',
    });
    expect(bucketToAsset(PROJECT, { name: 'logs' })).toMatchObject({
      kind: 'cloud_resource',
      externalKey: `gcp:${PROJECT}:gcs:logs`,
      source: 'gcp',
    });
  });
});

describe('parseAggregatedInstances', () => {
  it('reads instances from the aggregated list JSON', () => {
    const json = JSON.parse(instanceBody(['web-1', 'web-2'])) as unknown;
    expect(parseAggregatedInstances(json).map((i) => i.name)).toEqual(['web-1', 'web-2']);
  });
});

describe('GcpConnector.discover', () => {
  it('inventories GCE and GCS as cloud_resource against allowlisted Google hosts', async () => {
    setGcpCreds();
    const fetchFn = stubGcp({ instances: [['web-1']], buckets: ['acme-logs'] });
    const assets = (await collect(new GcpConnector().discover(ctx()))) as Array<{
      kind: string;
      source: string;
      externalKey: string;
    }>;
    expect(assets.every((a) => a.kind === 'cloud_resource')).toBe(true);
    expect(assets.every((a) => a.source === 'gcp')).toBe(true);
    expect(assets.map((a) => a.externalKey)).toEqual(
      expect.arrayContaining([
        `gcp:${PROJECT}:gce:us-central1-a:web-1`,
        `gcp:${PROJECT}:gcs:acme-logs`,
      ]),
    );
    for (const [url] of fetchFn.mock.calls) {
      const host = new URL(String(url)).hostname;
      expect(host.endsWith('googleapis.com')).toBe(true);
      expect(host).not.toContain('evil');
    }
    expect(String(fetchFn.mock.calls[0][0])).toBe('https://oauth2.googleapis.com/token');
    expect(
      fetchFn.mock.calls.some(([url]) =>
        String(url).startsWith(
          `https://compute.googleapis.com/compute/v1/projects/${PROJECT}/aggregated/instances`,
        ),
      ),
    ).toBe(true);
    expect(
      fetchFn.mock.calls.some(([url]) => String(url).includes('https://storage.googleapis.com/storage/v1/b')),
    ).toBe(true);
  });

  it('fails closed when GCP_* credentials are missing', async () => {
    const fetchFn = stubGcp({ instances: [['web-1']] });
    await expect(collect(new GcpConnector().discover(ctx()))).rejects.toThrow(/cannot be used/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when credentialRef is unset — no unauthenticated listing', async () => {
    setGcpCreds();
    const fetchFn = stubGcp({ instances: [['web-1']] });
    await expect(collect(new GcpConnector().discover(ctx({ projectId: PROJECT }, null)))).rejects.toThrow(
      /env:GCP_\*/,
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses a tenant-writable endpoint and never sends keys there', async () => {
    setGcpCreds();
    const fetchFn = stubGcp({ instances: [['web-1']] });
    await expect(
      collect(
        new GcpConnector().discover(
          ctx({
            projectId: PROJECT,
            endpoint: 'https://evil.example',
            apiUrl: 'https://evil.example/gcp',
            host: 'evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable GCP endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('does not take a tenant-supplied host even when mixed with a valid projectId', async () => {
    setGcpCreds();
    const fetchFn = stubGcp({ instances: [['web-1']], buckets: [] });
    await expect(
      collect(
        new GcpConnector().discover(
          ctx({
            projectId: PROJECT,
            customEndpoint: 'https://compute.googleapis.com.evil.example',
            tokenUri: 'https://evil.example/token',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable GCP endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('requires a valid GCP project identifier', async () => {
    setGcpCreds();
    await expect(
      collect(new GcpConnector().discover(ctx({ projectId: 'acme-prod.evil.example' }))),
    ).rejects.toThrow(/projectId|project identifier/);
  });

  it('succeeds on a last page of GCP_PER_PAGE with no nextPageToken', async () => {
    setGcpCreds();
    const names = Array.from({ length: GCP_PER_PAGE }, (_, i) => `web-full-${i}`);
    const fetchFn = stubGcp({ instances: [names], buckets: [] });
    const assets = (await collect(
      new GcpConnector().discover(ctx({ projectId: PROJECT, resourceTypes: ['gce_instance'] })),
    )) as Array<{ externalKey: string }>;
    expect(assets).toHaveLength(GCP_PER_PAGE);
    expect(assets.map((a) => a.externalKey)).toEqual(
      names.map((name) => `gcp:${PROJECT}:gce:us-central1-a:${name}`),
    );
    const instanceCalls = fetchFn.mock.calls.filter(([url]) =>
      String(url).includes('/aggregated/instances'),
    );
    expect(instanceCalls).toHaveLength(1);
  });

  it('fails when an instance listing is truncated at the page cap', async () => {
    setGcpCreds();
    const pages = Array.from({ length: GCP_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: GCP_PER_PAGE }, (_, i) => `web-${p}-${i}`),
    );
    const fetchFn = stubGcp({ instances: pages, buckets: [] });
    await expect(
      collect(
        new GcpConnector().discover(ctx({ projectId: PROJECT, resourceTypes: ['gce_instance'] })),
      ),
    ).rejects.toThrow(/truncated/);
    const instanceCalls = fetchFn.mock.calls.filter(([url]) =>
      String(url).includes('/aggregated/instances'),
    );
    expect(instanceCalls).toHaveLength(GCP_MAX_PAGES);
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    setGcpCreds();
    stubGcp({ status: 403 });
    await expect(collect(new GcpConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(
      collect(new GcpConnector().discover(ctx({ projectId: PROJECT }, 'vault:gcp'))),
    ).rejects.toThrow(/Unsupported credentialRef scheme/);
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret', async () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    await expect(
      collect(new GcpConnector().discover(ctx({ projectId: PROJECT }, 'env:DATABASE_URL'))),
    ).rejects.toThrow(/not allowlisted/);
  });
});

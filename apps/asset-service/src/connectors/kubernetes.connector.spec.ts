import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  K8S_MAX_PAGES,
  K8S_PER_PAGE,
  KubernetesConnector,
  clusterToAsset,
  kubernetesExternalKey,
  parseAksClusters,
  parseEksCluster,
  parseEksClusterNames,
  parseGkeClusters,
  type KubernetesCluster,
} from './kubernetes.connector';
import type { DiscoveryContext } from './connector.registry';

const ACCOUNT = '123456789012';
const REGION = 'us-east-1';
const PROJECT = 'acme-prod';
const SUB = '11111111-1111-1111-1111-111111111111';
const TENANT = '22222222-2222-2222-2222-222222222222';
const CLIENT = '33333333-3333-3333-3333-333333333333';

const gcpPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

const ctx = (
  config: Record<string, unknown>,
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

function setAwsCreds(): void {
  process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
  process.env.AWS_SECRET_ACCESS_KEY = 'secret';
}

function setGcpCreds(): void {
  process.env.GCP_CLIENT_EMAIL = 'ctem-discovery@acme-prod.iam.gserviceaccount.com';
  process.env.GCP_PRIVATE_KEY = gcpPem;
}

function setAzureCreds(): void {
  process.env.AZURE_TENANT_ID = TENANT;
  process.env.AZURE_CLIENT_ID = CLIENT;
  process.env.AZURE_CLIENT_SECRET = 's3cret';
}

function eksClusterBody(name: string, over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    cluster: {
      name,
      arn: `arn:aws:eks:${REGION}:${ACCOUNT}:cluster/${name}`,
      version: '1.29',
      status: 'ACTIVE',
      endpoint: 'https://ABCDEF.gr7.us-east-1.eks.amazonaws.com',
      tags: { env: 'prod' },
      resourcesVpcConfig: { endpointPublicAccess: true },
      ...over,
    },
  });
}

function stubAws(opts: {
  names?: string[][];
  nameNext?: Array<string | undefined>;
  status?: number;
}): ReturnType<typeof vi.fn> {
  const page = { n: 0 };
  const fn = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const href = String(url);
    const parsed = new URL(href);
    const body = String(init?.body ?? '');
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (href.includes('sts.') && body.includes('GetCallerIdentity')) {
      return new Response(callerXml(), { status: 200 });
    }
    if (parsed.hostname === `api.eks.${REGION}.amazonaws.com`) {
      if (parsed.pathname === '/clusters') {
        const i = page.n;
        const names = opts.names?.[i] ?? [];
        const more = i < (opts.names?.length ?? 1) - 1;
        const next = opts.nameNext?.[i] ?? (more ? `more-${i + 1}` : undefined);
        page.n += 1;
        return new Response(JSON.stringify({ clusters: names, ...(next ? { nextToken: next } : {}) }), {
          status: 200,
        });
      }
      const name = decodeURIComponent(parsed.pathname.replace('/clusters/', ''));
      return new Response(eksClusterBody(name), { status: 200 });
    }
    return new Response('unexpected', { status: 500 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function stubGcp(opts: {
  clusters?: Array<Array<{ name: string; location?: string; id?: string }>>;
  next?: Array<string | undefined>;
  status?: number;
}): ReturnType<typeof vi.fn> {
  const page = { n: 0 };
  const fn = vi.fn(async (url: string | URL) => {
    const parsed = new URL(String(url));
    if (parsed.hostname === 'oauth2.googleapis.com') {
      return new Response(JSON.stringify({ access_token: 'ya29.test' }), { status: 200 });
    }
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (parsed.hostname === 'container.googleapis.com') {
      const i = page.n;
      const items = opts.clusters?.[i] ?? [];
      const more = i < (opts.clusters?.length ?? 1) - 1;
      const next = opts.next?.[i] ?? (more ? `page-${i + 1}` : undefined);
      page.n += 1;
      return new Response(
        JSON.stringify({
          clusters: items.map((c) => ({
            name: c.name,
            location: c.location ?? 'us-central1',
            id: c.id ?? '1',
            status: 'RUNNING',
            currentMasterVersion: '1.29',
            endpoint: '35.188.1.2',
            resourceLabels: { team: 'payments' },
          })),
          ...(next ? { nextPageToken: next } : {}),
        }),
        { status: 200 },
      );
    }
    return new Response('unexpected', { status: 500 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function stubAzure(opts: {
  clusters?: Array<Array<{ name: string; rg: string }>>;
  next?: Array<string | undefined>;
  status?: number;
}): ReturnType<typeof vi.fn> {
  const page = { n: 0 };
  const fn = vi.fn(async (url: string | URL) => {
    const parsed = new URL(String(url));
    if (parsed.hostname === 'login.microsoftonline.com') {
      return new Response(JSON.stringify({ access_token: 'eyJtest' }), { status: 200 });
    }
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (parsed.hostname === 'management.azure.com') {
      const i = page.n;
      const items = opts.clusters?.[i] ?? [];
      const more = i < (opts.clusters?.length ?? 1) - 1;
      const next =
        opts.next?.[i] ??
        (more
          ? `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.ContainerService/managedClusters?api-version=2024-09-01&skiptoken=${i + 1}`
          : undefined);
      page.n += 1;
      return new Response(
        JSON.stringify({
          value: items.map((c) => ({
            name: c.name,
            id: `/subscriptions/${SUB}/resourceGroups/${c.rg}/providers/Microsoft.ContainerService/managedClusters/${c.name}`,
            location: 'eastus',
            tags: { env: 'prod' },
            properties: {
              kubernetesVersion: '1.29.0',
              provisioningState: 'Succeeded',
              fqdn: `${c.name}-xxx.hcp.eastus.azmk8s.io`,
              apiServerAccessProfile: { enablePrivateCluster: false },
            },
          })),
          ...(next ? { nextLink: next } : {}),
        }),
        { status: 200 },
      );
    }
    return new Response('unexpected', { status: 500 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.GCP_CLIENT_EMAIL;
  delete process.env.GCP_PRIVATE_KEY;
  delete process.env.AZURE_TENANT_ID;
  delete process.env.AZURE_CLIENT_ID;
  delete process.env.AZURE_CLIENT_SECRET;
  delete process.env.GITHUB_TOKEN;
});

describe('clusterToAsset / externalKey', () => {
  const awsCluster: KubernetesCluster = {
    cloud: 'aws',
    scope: `${ACCOUNT}:${REGION}`,
    name: 'prod',
    clusterIdentity: 'prod',
    accountId: ACCOUNT,
    region: REGION,
    arn: `arn:aws:eks:${REGION}:${ACCOUNT}:cluster/prod`,
    tags: { env: 'prod' },
    exposure: 'internet_facing',
  };

  it('is stable across remaps and keeps tags in attributes only', () => {
    const a = clusterToAsset(awsCluster);
    const b = clusterToAsset({ ...awsCluster, tags: { env: 'prod', extra: 'x' } });
    expect(a.externalKey).toBe(`k8s:aws:${ACCOUNT}:${REGION}:prod:_:Cluster:prod`);
    expect(a.externalKey).toBe(kubernetesExternalKey(awsCluster));
    expect(b.externalKey).toBe(a.externalKey);
    expect(a.kind).toBe('kubernetes_workload');
    expect(a.source).toBe('kubernetes');
    expect(a.attributes).toMatchObject({
      cloud: 'aws',
      workloadKind: 'Cluster',
      namespace: '_',
      tags: { env: 'prod' },
    });
    expect(a.tags).toBeUndefined();
  });

  it('includes a safe UID and omits colon-heavy ARNs from the key', () => {
    expect(
      kubernetesExternalKey({
        ...awsCluster,
        cloud: 'gcp',
        scope: PROJECT,
        clusterIdentity: 'us-central1/prod',
        uid: '12345',
      }),
    ).toBe('k8s:gcp:acme-prod:us-central1/prod:_:Cluster:prod:12345');
    expect(kubernetesExternalKey(awsCluster)).not.toContain('arn:aws');
  });
});

describe('parsers', () => {
  it('parses EKS names and describe payloads without using endpoint as a URL', () => {
    expect(parseEksClusterNames({ clusters: ['prod', 'dev'] })).toEqual(['prod', 'dev']);
    const cluster = parseEksCluster(JSON.parse(eksClusterBody('prod')), REGION, ACCOUNT);
    expect(cluster.name).toBe('prod');
    expect(cluster.exposure).toBe('internet_facing');
    expect(JSON.stringify(cluster)).not.toContain('gr7');
  });

  it('parses GKE and AKS lists and ignores kube-apiserver hosts', () => {
    const gke = parseGkeClusters(
      {
        clusters: [
          {
            name: 'prod',
            location: 'us-central1',
            id: '99',
            endpoint: '35.188.1.2',
            privateClusterConfig: { enablePrivateEndpoint: true },
          },
        ],
      },
      PROJECT,
    );
    expect(gke[0]).toMatchObject({
      name: 'prod',
      clusterIdentity: 'us-central1/prod',
      uid: '99',
      exposure: 'internal',
    });
    const aks = parseAksClusters(
      {
        value: [
          {
            name: 'prod',
            id: `/subscriptions/${SUB}/resourceGroups/rg1/providers/Microsoft.ContainerService/managedClusters/prod`,
            properties: {
              fqdn: 'prod.hcp.eastus.azmk8s.io',
              apiServerAccessProfile: { enablePrivateCluster: true },
            },
          },
        ],
      },
      SUB,
    );
    expect(aks[0]).toMatchObject({
      name: 'prod',
      clusterIdentity: 'rg1/prod',
      exposure: 'internal',
    });
    expect(JSON.stringify(aks[0])).not.toContain('hcp.eastus');
  });
});

describe('KubernetesConnector.discover', () => {
  it('inventories EKS clusters as kubernetes_workload on api.eks', async () => {
    setAwsCreds();
    const fetchFn = stubAws({ names: [['prod', 'dev']] });
    const assets = (await collect(
      new KubernetesConnector().discover(ctx({ cloud: 'aws', region: REGION })),
    )) as Array<{ externalKey: string; kind: string; source: string; attributes: { cloud: string } }>;
    expect(assets.map((a) => a.externalKey)).toEqual([
      `k8s:aws:${ACCOUNT}:${REGION}:prod:_:Cluster:prod`,
      `k8s:aws:${ACCOUNT}:${REGION}:dev:_:Cluster:dev`,
    ]);
    expect(assets.every((a) => a.kind === 'kubernetes_workload')).toBe(true);
    expect(assets.every((a) => a.source === 'kubernetes')).toBe(true);
    expect(assets.every((a) => a.attributes.cloud === 'aws')).toBe(true);
    const hosts = fetchFn.mock.calls.map(([url]) => new URL(String(url)).hostname);
    expect(hosts.every((h) => h.endsWith('amazonaws.com'))).toBe(true);
    expect(hosts.some((h) => h === `api.eks.${REGION}.amazonaws.com`)).toBe(true);
    expect(hosts.some((h) => h.includes('gr7'))).toBe(false);
  });

  it('inventories GKE clusters as kubernetes_workload on container.googleapis.com', async () => {
    setGcpCreds();
    const fetchFn = stubGcp({ clusters: [[{ name: 'prod', id: '7' }]] });
    const assets = (await collect(
      new KubernetesConnector().discover(
        ctx({ cloud: 'gcp', projectId: PROJECT }, 'env:GCP_CLIENT_EMAIL'),
      ),
    )) as Array<{ externalKey: string }>;
    expect(assets.map((a) => a.externalKey)).toEqual([
      'k8s:gcp:acme-prod:us-central1/prod:_:Cluster:prod:7',
    ]);
    const hosts = fetchFn.mock.calls.map(([url]) => new URL(String(url)).hostname);
    expect(hosts).toEqual(['oauth2.googleapis.com', 'container.googleapis.com']);
  });

  it('inventories AKS clusters as kubernetes_workload on ARM', async () => {
    setAzureCreds();
    const fetchFn = stubAzure({ clusters: [[{ name: 'prod', rg: 'rg1' }]] });
    const assets = (await collect(
      new KubernetesConnector().discover(
        ctx({ cloud: 'azure', subscriptionId: SUB }, 'env:AZURE_CLIENT_SECRET'),
      ),
    )) as Array<{ externalKey: string }>;
    expect(assets.map((a) => a.externalKey)).toEqual([
      `k8s:azure:${SUB}:rg1/prod:_:Cluster:prod`,
    ]);
    const hosts = fetchFn.mock.calls.map(([url]) => new URL(String(url)).hostname);
    expect(hosts).toEqual(['login.microsoftonline.com', 'management.azure.com']);
  });

  it('refuses apiServerUrl and kubeconfig server and never fetches them', async () => {
    setAwsCreds();
    const fetchFn = stubAws({ names: [['prod']] });
    await expect(
      collect(
        new KubernetesConnector().discover(
          ctx({
            cloud: 'aws',
            region: REGION,
            apiServerUrl: 'https://10.0.0.12:6443',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable Kubernetes endpoint/);
    await expect(
      collect(
        new KubernetesConnector().discover(
          ctx({
            cloud: 'aws',
            region: REGION,
            kubeconfig: 'apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.1.2.3:6443\n',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable Kubernetes endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when the credential env does not match cloud', async () => {
    setAwsCreds();
    setGcpCreds();
    const fetchFn = stubAws({ names: [['prod']] });
    await expect(
      collect(
        new KubernetesConnector().discover(
          ctx({ cloud: 'aws', region: REGION }, 'env:GCP_CLIENT_EMAIL'),
        ),
      ),
    ).rejects.toThrow(/env:AWS_\*/);
    await expect(
      collect(
        new KubernetesConnector().discover(
          ctx({ cloud: 'gcp', projectId: PROJECT }, 'env:AWS_ACCESS_KEY_ID'),
        ),
      ),
    ).rejects.toThrow(/env:GCP_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when credentials are missing', async () => {
    const fetchFn = stubAws({ names: [['prod']] });
    await expect(
      collect(new KubernetesConnector().discover(ctx({ cloud: 'aws', region: REGION }))),
    ).rejects.toThrow(/cannot be used|fails closed|env:AWS_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('succeeds on a last page of K8S_PER_PAGE with no next token', async () => {
    setAwsCreds();
    const names = Array.from({ length: K8S_PER_PAGE }, (_, i) => `c-${i}`);
    const fetchFn = stubAws({ names: [names] });
    const assets = await collect(
      new KubernetesConnector().discover(ctx({ cloud: 'aws', region: REGION })),
    );
    expect(assets).toHaveLength(K8S_PER_PAGE);
    const listCalls = fetchFn.mock.calls.filter(([url]) => {
      const parsed = new URL(String(url));
      return parsed.hostname.startsWith('api.eks.') && parsed.pathname === '/clusters';
    });
    expect(listCalls).toHaveLength(1);
  });

  it('fails when listing is truncated at the page cap', async () => {
    setAwsCreds();
    const pages = Array.from({ length: K8S_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: K8S_PER_PAGE }, (_, i) => `c-${p}-${i}`),
    );
    const fetchFn = stubAws({ names: pages });
    await expect(
      collect(new KubernetesConnector().discover(ctx({ cloud: 'aws', region: REGION }))),
    ).rejects.toThrow(/truncated/);
    const listCalls = fetchFn.mock.calls.filter(([url]) => {
      const parsed = new URL(String(url));
      return parsed.hostname.startsWith('api.eks.') && parsed.pathname === '/clusters';
    });
    expect(listCalls).toHaveLength(K8S_MAX_PAGES);
  });

  it('refuses a leftover Azure nextLink off the ARM allowlist', async () => {
    setAzureCreds();
    stubAzure({
      clusters: [[{ name: 'prod', rg: 'rg1' }]],
      next: ['https://evil.example/next'],
    });
    await expect(
      collect(
        new KubernetesConnector().discover(
          ctx({ cloud: 'azure', subscriptionId: SUB }, 'env:AZURE_CLIENT_SECRET'),
        ),
      ),
    ).rejects.toThrow(/only management\.azure\.com/);
  });

  it('does not shell out to kubectl and does not dial kube-apiserver hosts', () => {
    const connector = readFileSync(join(__dirname, 'kubernetes.connector.ts'), 'utf8');
    const egress = readFileSync(join(__dirname, 'kubernetes.egress.ts'), 'utf8');
    const src = `${connector}\n${egress}`;
    expect(src).not.toMatch(/kubectl|child_process|spawn\(|execFile|execSync|helm /);
    expect(src).not.toMatch(/dkr\.ecr|\/blobs\/|admission/);
    expect(egress).toMatch(/api\.eks|container\.googleapis\.com|management\.azure\.com/);
    expect(src).toMatch(/Never read|Never dial|kube-apiserver/);
  });
});

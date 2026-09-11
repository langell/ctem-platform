import { NotFoundException } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { K8S_MAX_PAGES, K8S_PER_PAGE, KubernetesConnector } from './kubernetes.connector';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';

const ACCOUNT = '123456789012';
const REGION = 'us-east-1';

/**
 * Discovery loop against the real database: integration → EKS (stubbed
 * ListClusters / DescribeCluster) → kubernetes_workload upserts → stale
 * archival on the next sync. HTTP is mocked — no live AWS and no
 * kube-apiserver dial.
 */
describe('Kubernetes discovery (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let assets: AssetsService;
  let scheduler: DiscoverySchedulerService;
  let orgId: string;
  let orgBId: string;
  const events: Array<{ subject: string }> = [];
  let clusterNames: string[] = [];
  let clusterNext: string | undefined;
  let fetchStatus = 200;

  function callerXml(): string {
    return `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>${ACCOUNT}</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`;
  }

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    orgId = (await createOrg(owner)).id;
    orgBId = (await createOrg(owner)).id;

    await owner.integration.create({
      data: {
        orgId,
        provider: 'kubernetes',
        displayName: 'discovery-int-test',
        config: { cloud: 'aws', region: REGION },
        credentialRef: 'env:AWS_ACCESS_KEY_ID',
      },
    });
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    process.env.AWS_SECRET_ACCESS_KEY = 'secret';

    const bus = {
      publish: vi.fn(async (subject: string) => {
        events.push({ subject });
      }),
    } as unknown as EventBus;

    const registry = new ConnectorRegistry();
    registry.register(new KubernetesConnector());
    assets = new AssetsService(prisma, bus);
    scheduler = new DiscoverySchedulerService(prisma, registry, assets);

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        if (fetchStatus !== 200) return new Response('boom', { status: fetchStatus });
        const href = String(url);
        const parsed = new URL(href);
        expect(parsed.protocol).toBe('https:');
        expect(parsed.hostname.endsWith('amazonaws.com')).toBe(true);
        expect(parsed.hostname).not.toContain('gr7');
        expect(parsed.hostname).not.toMatch(/^\d+\.\d+\.\d+\.\d+$/);
        const body = String(init?.body ?? '');
        if (href.includes('sts.') && body.includes('GetCallerIdentity')) {
          return new Response(callerXml(), { status: 200 });
        }
        expect(parsed.hostname).toBe(`api.eks.${REGION}.amazonaws.com`);
        if (parsed.pathname === '/clusters') {
          return new Response(
            JSON.stringify({
              clusters: clusterNames,
              ...(clusterNext ? { nextToken: clusterNext } : {}),
            }),
            { status: 200 },
          );
        }
        const name = decodeURIComponent(parsed.pathname.replace('/clusters/', ''));
        return new Response(
          JSON.stringify({
            cluster: {
              name,
              arn: `arn:aws:eks:${REGION}:${ACCOUNT}:cluster/${name}`,
              status: 'ACTIVE',
              endpoint: 'https://ABCDEF.gr7.us-east-1.eks.amazonaws.com',
              resourcesVpcConfig: { endpointPublicAccess: false },
            },
          }),
          { status: 200 },
        );
      }),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    delete process.env.AWS_ACCESS_KEY_ID;
    delete process.env.AWS_SECRET_ACCESS_KEY;
    await owner.organization.deleteMany({ where: { id: { in: [orgId, orgBId] } } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('inventories EKS clusters as kubernetes_workload without dialing kube-apiserver', async () => {
    clusterNames = ['prod', 'dev'];
    clusterNext = undefined;
    fetchStatus = 200;
    const results = await scheduler.syncOrg(orgId);
    expect(results).toEqual([
      expect.objectContaining({ provider: 'kubernetes', upserted: 2, archived: 0, error: null }),
    ]);

    const rows = await owner.asset.findMany({ where: { orgId }, orderBy: { name: 'asc' } });
    expect(rows.map((a) => a.externalKey)).toEqual([
      `k8s:aws:${ACCOUNT}:${REGION}:dev:_:Cluster:dev`,
      `k8s:aws:${ACCOUNT}:${REGION}:prod:_:Cluster:prod`,
    ]);
    expect(rows.every((a) => a.kind === 'kubernetes_workload')).toBe(true);
    expect(rows.every((a) => a.source === 'kubernetes')).toBe(true);
    expect(events.filter((e) => e.subject === 'ctem.asset.discovered')).toHaveLength(2);
  });

  it('archives assets that stop appearing instead of deleting them', async () => {
    clusterNames = ['prod'];
    clusterNext = undefined;
    const [result] = await scheduler.syncOrg(orgId);
    expect(result).toMatchObject({ upserted: 1, archived: 1 });

    const dev = await owner.asset.findUnique({
      where: {
        orgId_externalKey: {
          orgId,
          externalKey: `k8s:aws:${ACCOUNT}:${REGION}:dev:_:Cluster:dev`,
        },
      },
    });
    expect(dev?.archivedAt).not.toBeNull();
  });

  it('GET-by-id on an org miss is 404, never 500 or empty-200', async () => {
    const owned = await owner.asset.findFirst({
      where: { orgId, source: 'kubernetes', archivedAt: null },
    });
    expect(owned).toBeTruthy();
    await expect(assets.get(orgBId, owned!.id)).rejects.toBeInstanceOf(NotFoundException);
  });

  it('does not archiveStale when listing is truncated at the page cap', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const keep = await owner.asset.create({
      data: {
        orgId,
        kind: 'kubernetes_workload',
        externalKey: `k8s:aws:${ACCOUNT}:${REGION}:keep:_:Cluster:keep`,
        name: 'keep',
        source: 'kubernetes',
        integrationId: first!.id,
      },
    });

    let page = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        const href = String(url);
        const parsed = new URL(href);
        expect(parsed.hostname.endsWith('amazonaws.com')).toBe(true);
        expect(parsed.hostname).not.toContain('gr7');
        const body = String(init?.body ?? '');
        if (href.includes('sts.') && body.includes('GetCallerIdentity')) {
          return new Response(callerXml(), { status: 200 });
        }
        if (parsed.pathname === '/clusters') {
          page += 1;
          const names = Array.from({ length: K8S_PER_PAGE }, (_, i) => `k8s-t-${page}-${i}`);
          const next = page <= K8S_MAX_PAGES ? `more-${page}` : undefined;
          return new Response(JSON.stringify({ clusters: names, ...(next ? { nextToken: next } : {}) }), {
            status: 200,
          });
        }
        return new Response(JSON.stringify({ cluster: { name: 'x', status: 'ACTIVE' } }), {
          status: 200,
        });
      }),
    );

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/truncated/);
    expect(result.archived).toBe(0);

    const kept = await owner.asset.findUnique({ where: { id: keep.id } });
    expect(kept?.archivedAt).toBeNull();
  });

  it('refuses a tenant kubeconfig / apiServerUrl without wiping inventory', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const bad = await owner.integration.create({
      data: {
        orgId,
        provider: 'kubernetes',
        displayName: 'exfil-apiserver',
        config: {
          cloud: 'aws',
          region: REGION,
          apiServerUrl: 'https://10.0.0.12:6443',
          kubeconfig: '/var/run/secrets/kubernetes.io/serviceaccount',
        },
        credentialRef: 'env:AWS_ACCESS_KEY_ID',
      },
    });

    const result = await scheduler.syncIntegration(bad);
    expect(result.error).toMatch(/tenant-writable Kubernetes endpoint/);
    expect(result.archived).toBe(0);

    const kept = await owner.asset.findMany({
      where: { orgId, source: 'kubernetes', integrationId: first!.id, archivedAt: null },
    });
    expect(kept.length).toBeGreaterThan(0);
  });
});

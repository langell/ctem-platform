import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';
import { GitHubConnector, type GitHubRepo } from './github.connector';

/**
 * The discovery loop against the real database: integration → GitHub (stubbed)
 * → asset upserts → stale archival on the next sync. Runs as ctem_app, so RLS
 * applies exactly as in deployment.
 */
describe('GitHub discovery (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let scheduler: DiscoverySchedulerService;
  let orgId: string;
  const events: Array<{ subject: string }> = [];
  let repos: GitHubRepo[] = [];

  const ghRepo = (name: string): GitHubRepo => ({
    name,
    full_name: `langell/${name}`,
    private: true,
    archived: false,
    fork: false,
    html_url: `https://github.com/langell/${name}`,
    default_branch: 'main',
    owner: { login: 'langell' },
  });

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    orgId = (await createOrg(owner)).id;

    await owner.integration.create({
      data: {
        orgId,
        provider: 'github',
        displayName: 'discovery-int-test',
        config: { owner: 'langell', ownerType: 'user' },
        credentialRef: 'env:DISCOVERY_INT_TOKEN',
      },
    });
    process.env.DISCOVERY_INT_TOKEN = 'stub-token';

    const bus = {
      publish: vi.fn(async (subject: string) => {
        events.push({ subject });
      }),
    } as unknown as EventBus;

    const registry = new ConnectorRegistry();
    registry.register(new GitHubConnector());
    scheduler = new DiscoverySchedulerService(prisma, registry, new AssetsService(prisma, bus));

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify(repos), { status: 200 })),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    delete process.env.DISCOVERY_INT_TOKEN;
    await owner.organization.deleteMany({ where: { id: orgId } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('inventories repositories as assets and publishes discovery events', async () => {
    repos = [ghRepo('svc-alpha'), ghRepo('svc-beta')];
    const results = await scheduler.syncOrg(orgId);
    expect(results).toEqual([
      expect.objectContaining({ provider: 'github', upserted: 2, archived: 0, error: null }),
    ]);

    const assets = await owner.asset.findMany({ where: { orgId }, orderBy: { name: 'asc' } });
    expect(assets.map((a) => a.externalKey)).toEqual([
      'github:langell/svc-alpha',
      'github:langell/svc-beta',
    ]);
    expect(events.filter((e) => e.subject === 'ctem.asset.discovered')).toHaveLength(2);

    const integration = await owner.integration.findFirst({ where: { orgId } });
    expect(integration?.lastSyncAt).not.toBeNull();
    expect(integration?.lastSyncError).toBeNull();
  });

  it('archives assets that stop appearing instead of deleting them', async () => {
    repos = [ghRepo('svc-alpha')]; // svc-beta vanished upstream
    const [result] = await scheduler.syncOrg(orgId);
    expect(result).toMatchObject({ upserted: 1, archived: 1 });

    const beta = await owner.asset.findUnique({
      where: { orgId_externalKey: { orgId, externalKey: 'github:langell/svc-beta' } },
    });
    expect(beta?.archivedAt).not.toBeNull();
  });

  it('records connector failures on the integration row', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('boom', { status: 500 })));
    const [result] = await scheduler.syncOrg(orgId);
    expect(result.error).toMatch(/500/);

    const integration = await owner.integration.findFirst({ where: { orgId } });
    expect(integration?.lastSyncError).toMatch(/500/);
  });
});

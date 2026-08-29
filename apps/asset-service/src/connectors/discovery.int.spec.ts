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
  let orgBId: string;
  const events: Array<{ subject: string }> = [];
  let repos: GitHubRepo[] = [];

  const ghRepo = (name: string, ownerLogin = 'langell'): GitHubRepo => ({
    name,
    full_name: `${ownerLogin}/${name}`,
    private: true,
    archived: false,
    fork: false,
    html_url: `https://github.com/${ownerLogin}/${name}`,
    default_branch: 'main',
    owner: { login: ownerLogin },
  });

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    orgId = (await createOrg(owner)).id;
    orgBId = (await createOrg(owner)).id;

    await owner.integration.create({
      data: {
        orgId,
        provider: 'github',
        displayName: 'discovery-int-test',
        config: { owner: 'langell', ownerType: 'user' },
        credentialRef: 'env:GITHUB_INT_TOKEN',
      },
    });
    process.env.GITHUB_INT_TOKEN = 'stub-token';

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
    delete process.env.GITHUB_INT_TOKEN;
    await owner.organization.deleteMany({ where: { id: { in: [orgId, orgBId] } } });
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
    const integration = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    expect(assets.every((a) => a.integrationId === integration?.id)).toBe(true);
    expect(events.filter((e) => e.subject === 'ctem.asset.discovered')).toHaveLength(2);

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

  it("does not archive another GitHub integration's assets in the same org", async () => {
    const other = await owner.integration.create({
      data: {
        orgId,
        provider: 'github',
        displayName: 'discovery-int-other',
        config: { owner: 'acme', ownerType: 'user' },
        credentialRef: 'env:GITHUB_INT_TOKEN',
      },
    });

    repos = [ghRepo('svc-alpha'), ghRepo('acme-api', 'acme')];
    await scheduler.syncOrg(orgId);

    const acme = await owner.asset.findUnique({
      where: { orgId_externalKey: { orgId, externalKey: 'github:acme/acme-api' } },
    });
    expect(acme?.archivedAt).toBeNull();
    expect(acme?.integrationId).toBe(other.id);

    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    expect(first).toBeTruthy();

    repos = [];
    const result = await scheduler.syncIntegration(first!);
    expect(result).toMatchObject({ upserted: 0, error: null });
    expect(result.archived).toBeGreaterThanOrEqual(1);

    const alpha = await owner.asset.findUnique({
      where: { orgId_externalKey: { orgId, externalKey: 'github:langell/svc-alpha' } },
    });
    expect(alpha?.archivedAt).not.toBeNull();

    const acmeAfter = await owner.asset.findUnique({
      where: { orgId_externalKey: { orgId, externalKey: 'github:acme/acme-api' } },
    });
    expect(acmeAfter?.archivedAt).toBeNull();
  });

  it("does not leak assets to a second org and does not touch that org's integrations", async () => {
    const other = await owner.integration.create({
      data: {
        orgId: orgBId,
        provider: 'github',
        displayName: 'org-b-github',
        config: { owner: 'other', ownerType: 'user' },
        credentialRef: 'env:GITHUB_INT_TOKEN',
      },
    });
    await owner.asset.create({
      data: {
        orgId: orgBId,
        kind: 'repository',
        externalKey: 'github:other/secret',
        name: 'secret',
        source: 'github',
        integrationId: other.id,
      },
    });

    repos = [ghRepo('acme-api', 'acme')];
    await scheduler.syncOrg(orgId);

    const fromB = await prisma.withOrg(orgBId, (tx) => tx.asset.findMany());
    expect(fromB.map((a) => a.externalKey)).toEqual(['github:other/secret']);
    expect(fromB.some((a) => a.externalKey.startsWith('github:langell/'))).toBe(false);
    expect(fromB.some((a) => a.externalKey === 'github:acme/acme-api')).toBe(false);

    const bAfter = await owner.integration.findUnique({ where: { id: other.id } });
    expect(bAfter?.lastSyncAt).toBeNull();
    expect(bAfter?.lastSyncError).toBeNull();
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret', async () => {
    const previous = process.env.DATABASE_URL;
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    const bad = await owner.integration.create({
      data: {
        orgId,
        provider: 'github',
        displayName: 'exfil-attempt',
        config: { owner: 'langell', ownerType: 'user' },
        credentialRef: 'env:DATABASE_URL',
      },
    });

    const result = await scheduler.syncIntegration(bad);
    expect(result.error).toMatch(/not allowlisted/);
    expect(result.error).not.toMatch(/postgres:\/\//);

    const row = await owner.integration.findUnique({ where: { id: bad.id } });
    expect(row?.lastSyncError).toMatch(/not allowlisted/);

    if (previous === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = previous;
  });

  it('records connector failures on the integration row', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('boom', { status: 500 })));
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/500/);

    const integration = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    expect(integration?.lastSyncError).toMatch(/500/);
  });
});

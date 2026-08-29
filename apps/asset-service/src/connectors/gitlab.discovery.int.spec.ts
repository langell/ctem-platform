import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';
import { GitLabConnector, type GitLabProject } from './gitlab.connector';

/**
 * The discovery loop against the real database: integration → GitLab (stubbed)
 * → asset upserts → stale archival on the next sync. Runs as ctem_app, so RLS
 * applies exactly as in deployment. HTTP is mocked — no live GitLab.
 */
describe('GitLab discovery (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let scheduler: DiscoverySchedulerService;
  let orgId: string;
  let orgBId: string;
  const events: Array<{ subject: string }> = [];
  let projects: GitLabProject[] = [];
  let fetchStatus = 200;

  const glProject = (path: string, ns = 'langell', visibility: GitLabProject['visibility'] = 'private'): GitLabProject => ({
    name: path,
    path,
    path_with_namespace: `${ns}/${path}`,
    visibility,
    archived: false,
    web_url: `https://gitlab.com/${ns}/${path}`,
    default_branch: 'main',
    namespace: { path: ns.split('/')[0], full_path: ns },
  });

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    orgId = (await createOrg(owner)).id;
    orgBId = (await createOrg(owner)).id;

    await owner.integration.create({
      data: {
        orgId,
        provider: 'gitlab',
        displayName: 'discovery-int-test',
        config: { owner: 'langell', ownerType: 'user' },
        credentialRef: 'env:GITLAB_INT_TOKEN',
      },
    });
    process.env.GITLAB_INT_TOKEN = 'stub-token';

    const bus = {
      publish: vi.fn(async (subject: string) => {
        events.push({ subject });
      }),
    } as unknown as EventBus;

    const registry = new ConnectorRegistry();
    registry.register(new GitLabConnector());
    scheduler = new DiscoverySchedulerService(prisma, registry, new AssetsService(prisma, bus));

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify(projects), { status: fetchStatus })),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    delete process.env.GITLAB_INT_TOKEN;
    await owner.organization.deleteMany({ where: { id: { in: [orgId, orgBId] } } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('inventories projects as assets and publishes discovery events', async () => {
    projects = [glProject('svc-alpha'), glProject('svc-beta')];
    fetchStatus = 200;
    const results = await scheduler.syncOrg(orgId);
    expect(results).toEqual([
      expect.objectContaining({ provider: 'gitlab', upserted: 2, archived: 0, error: null }),
    ]);

    const assets = await owner.asset.findMany({ where: { orgId }, orderBy: { name: 'asc' } });
    expect(assets.map((a) => a.externalKey)).toEqual([
      'gitlab:langell/svc-alpha',
      'gitlab:langell/svc-beta',
    ]);
    const integration = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    expect(assets.every((a) => a.integrationId === integration?.id)).toBe(true);
    expect(assets.every((a) => (a.attributes as { cloneUrl?: string }).cloneUrl?.startsWith('https://gitlab.com/'))).toBe(
      true,
    );
    expect(events.filter((e) => e.subject === 'ctem.asset.discovered')).toHaveLength(2);

    expect(integration?.lastSyncAt).not.toBeNull();
    expect(integration?.lastSyncError).toBeNull();
  });

  it('archives assets that stop appearing instead of deleting them', async () => {
    projects = [glProject('svc-alpha')];
    fetchStatus = 200;
    const [result] = await scheduler.syncOrg(orgId);
    expect(result).toMatchObject({ upserted: 1, archived: 1 });

    const beta = await owner.asset.findUnique({
      where: { orgId_externalKey: { orgId, externalKey: 'gitlab:langell/svc-beta' } },
    });
    expect(beta?.archivedAt).not.toBeNull();
  });

  it("does not archive another GitLab integration's assets in the same org", async () => {
    const other = await owner.integration.create({
      data: {
        orgId,
        provider: 'gitlab',
        displayName: 'discovery-int-other',
        config: { owner: 'acme', ownerType: 'group' },
        credentialRef: 'env:GITLAB_INT_TOKEN',
      },
    });

    projects = [glProject('svc-alpha'), glProject('acme-api', 'acme')];
    fetchStatus = 200;
    await scheduler.syncOrg(orgId);

    const acme = await owner.asset.findUnique({
      where: { orgId_externalKey: { orgId, externalKey: 'gitlab:acme/acme-api' } },
    });
    expect(acme?.archivedAt).toBeNull();
    expect(acme?.integrationId).toBe(other.id);

    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    expect(first).toBeTruthy();

    projects = [];
    fetchStatus = 200;
    const result = await scheduler.syncIntegration(first!);
    expect(result).toMatchObject({ upserted: 0, error: null });
    expect(result.archived).toBeGreaterThanOrEqual(1);

    const alpha = await owner.asset.findUnique({
      where: { orgId_externalKey: { orgId, externalKey: 'gitlab:langell/svc-alpha' } },
    });
    expect(alpha?.archivedAt).not.toBeNull();

    const acmeAfter = await owner.asset.findUnique({
      where: { orgId_externalKey: { orgId, externalKey: 'gitlab:acme/acme-api' } },
    });
    expect(acmeAfter?.archivedAt).toBeNull();
  });

  it("does not leak assets to a second org and does not touch that org's integrations", async () => {
    const other = await owner.integration.create({
      data: {
        orgId: orgBId,
        provider: 'gitlab',
        displayName: 'org-b-gitlab',
        config: { owner: 'other', ownerType: 'user' },
        credentialRef: 'env:GITLAB_INT_TOKEN',
      },
    });
    await owner.asset.create({
      data: {
        orgId: orgBId,
        kind: 'repository',
        externalKey: 'gitlab:other/secret',
        name: 'secret',
        source: 'gitlab',
        integrationId: other.id,
      },
    });

    projects = [glProject('acme-api', 'acme')];
    fetchStatus = 200;
    await scheduler.syncOrg(orgId);

    const fromB = await prisma.withOrg(orgBId, (tx) => tx.asset.findMany());
    expect(fromB.map((a) => a.externalKey)).toEqual(['gitlab:other/secret']);
    expect(fromB.some((a) => a.externalKey.startsWith('gitlab:langell/'))).toBe(false);
    expect(fromB.some((a) => a.externalKey === 'gitlab:acme/acme-api')).toBe(false);

    const bAfter = await owner.integration.findUnique({ where: { id: other.id } });
    expect(bAfter?.lastSyncAt).toBeNull();
    expect(bAfter?.lastSyncError).toBeNull();
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret or wiping inventory', async () => {
    const previous = process.env.DATABASE_URL;
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    const existing = await owner.asset.create({
      data: {
        orgId,
        kind: 'repository',
        externalKey: 'gitlab:langell/keep-me',
        name: 'keep-me',
        source: 'gitlab',
        integrationId: (
          await owner.integration.findFirst({
            where: { orgId, displayName: 'discovery-int-test' },
          })
        )?.id,
      },
    });

    const bad = await owner.integration.create({
      data: {
        orgId,
        provider: 'gitlab',
        displayName: 'exfil-attempt',
        config: { owner: 'langell', ownerType: 'user' },
        credentialRef: 'env:DATABASE_URL',
      },
    });

    const result = await scheduler.syncIntegration(bad);
    expect(result.error).toMatch(/not allowlisted/);
    expect(result.error).not.toMatch(/postgres:\/\//);
    expect(result.archived).toBe(0);

    const row = await owner.integration.findUnique({ where: { id: bad.id } });
    expect(row?.lastSyncError).toMatch(/not allowlisted/);

    const kept = await owner.asset.findUnique({ where: { id: existing.id } });
    expect(kept?.archivedAt).toBeNull();

    if (previous === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = previous;
  });

  it('does not archive inventory when a set credentialRef is empty', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const token = process.env.GITLAB_INT_TOKEN;
    delete process.env.GITLAB_INT_TOKEN;

    const before = await owner.asset.findMany({
      where: { orgId, source: 'gitlab', integrationId: first!.id, archivedAt: null },
    });
    expect(before.length).toBeGreaterThan(0);

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/cannot be used/);
    expect(result.archived).toBe(0);

    const after = await owner.asset.findMany({
      where: { orgId, source: 'gitlab', integrationId: first!.id, archivedAt: null },
    });
    expect(after.length).toBe(before.length);

    process.env.GITLAB_INT_TOKEN = token;
  });

  it('does not archive when a private user profile would 200 empty on /users/:id/projects', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const keep = await owner.asset.create({
      data: {
        orgId,
        kind: 'repository',
        externalKey: 'gitlab:langell/private-keep',
        name: 'private-keep',
        source: 'gitlab',
        integrationId: first!.id,
      },
    });

    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.includes('/users/')) {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      return new Response(JSON.stringify([glProject('private-keep')]), { status: 200 });
    });
    vi.stubGlobal('fetch', fetchFn);

    const result = await scheduler.syncIntegration(first!);
    const called = String(fetchFn.mock.calls[0][0]);
    expect(called).toContain('/projects?owned=true');
    expect(called).not.toContain('/users/');
    expect(result.error).toBeNull();
    expect(result.upserted).toBeGreaterThanOrEqual(1);

    const kept = await owner.asset.findUnique({ where: { id: keep.id } });
    expect(kept?.archivedAt).toBeNull();

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify(projects), { status: fetchStatus })),
    );
  });

  it('records connector failures on the integration row and does not wipe inventory', async () => {
    fetchStatus = 500;
    projects = [];
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const before = await owner.asset.findMany({
      where: { orgId, source: 'gitlab', integrationId: first!.id, archivedAt: null },
    });

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/500/);
    expect(result.archived).toBe(0);

    const integration = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    expect(integration?.lastSyncError).toMatch(/500/);

    const after = await owner.asset.findMany({
      where: { orgId, source: 'gitlab', integrationId: first!.id, archivedAt: null },
    });
    expect(after.length).toBe(before.length);
    fetchStatus = 200;
  });
});

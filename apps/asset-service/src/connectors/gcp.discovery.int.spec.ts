import { NotFoundException } from '@nestjs/common';
import { generateKeyPairSync } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { GCP_MAX_PAGES, GCP_PER_PAGE, GcpConnector } from './gcp.connector';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';

const PROJECT = 'acme-prod';
const gcpPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

/**
 * The discovery loop against the real database: integration → GCP (stubbed)
 * → asset upserts → stale archival on the next sync. Runs as ctem_app, so RLS
 * applies exactly as in deployment. HTTP is mocked — no live GCP.
 */
describe('GCP discovery (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let assets: AssetsService;
  let scheduler: DiscoverySchedulerService;
  let orgId: string;
  let orgBId: string;
  const events: Array<{ subject: string }> = [];
  let instanceNames: string[] = [];
  let nextToken: string | undefined;
  let fetchStatus = 200;

  function instancesJson(): string {
    const instances = instanceNames.map((name) => ({
      name,
      zone: `https://www.googleapis.com/compute/v1/projects/${PROJECT}/zones/us-central1-a`,
      status: 'RUNNING',
      networkInterfaces: [{ networkIP: '10.128.0.2' }],
    }));
    return JSON.stringify({
      items: { 'zones/us-central1-a': { instances } },
      ...(nextToken ? { nextPageToken: nextToken } : {}),
    });
  }

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    orgId = (await createOrg(owner)).id;
    orgBId = (await createOrg(owner)).id;

    await owner.integration.create({
      data: {
        orgId,
        provider: 'gcp',
        displayName: 'discovery-int-test',
        config: { projectId: PROJECT, resourceTypes: ['gce_instance'] },
        credentialRef: 'env:GCP_CLIENT_EMAIL',
      },
    });
    process.env.GCP_CLIENT_EMAIL = 'ctem-discovery@acme-prod.iam.gserviceaccount.com';
    process.env.GCP_PRIVATE_KEY = gcpPem;

    const bus = {
      publish: vi.fn(async (subject: string) => {
        events.push({ subject });
      }),
    } as unknown as EventBus;

    const registry = new ConnectorRegistry();
    registry.register(new GcpConnector());
    assets = new AssetsService(prisma, bus);
    scheduler = new DiscoverySchedulerService(prisma, registry, assets);

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const parsed = new URL(String(url));
        if (parsed.hostname === 'oauth2.googleapis.com') {
          return new Response(JSON.stringify({ access_token: 'ya29.test' }), { status: 200 });
        }
        if (fetchStatus !== 200) return new Response('boom', { status: fetchStatus });
        if (parsed.pathname.includes('/aggregated/instances')) {
          return new Response(instancesJson(), { status: 200 });
        }
        return new Response('unexpected', { status: 500 });
      }),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    delete process.env.GCP_CLIENT_EMAIL;
    delete process.env.GCP_PRIVATE_KEY;
    await owner.organization.deleteMany({ where: { id: { in: [orgId, orgBId] } } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('inventories GCP resources as cloud_resource and publishes discovery events', async () => {
    instanceNames = ['web-alpha', 'web-beta'];
    nextToken = undefined;
    fetchStatus = 200;
    const results = await scheduler.syncOrg(orgId);
    expect(results).toEqual([
      expect.objectContaining({ provider: 'gcp', upserted: 2, archived: 0, error: null }),
    ]);

    const rows = await owner.asset.findMany({ where: { orgId }, orderBy: { name: 'asc' } });
    expect(rows.map((a) => a.externalKey)).toEqual([
      `gcp:${PROJECT}:gce:us-central1-a:web-alpha`,
      `gcp:${PROJECT}:gce:us-central1-a:web-beta`,
    ]);
    expect(rows.every((a) => a.kind === 'cloud_resource')).toBe(true);
    expect(rows.every((a) => a.source === 'gcp')).toBe(true);
    expect(events.filter((e) => e.subject === 'ctem.asset.discovered')).toHaveLength(2);

    const integration = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    expect(rows.every((a) => a.integrationId === integration?.id)).toBe(true);
    expect(integration?.lastSyncAt).not.toBeNull();
    expect(integration?.lastSyncError).toBeNull();
  });

  it('archives assets that stop appearing instead of deleting them', async () => {
    instanceNames = ['web-alpha'];
    nextToken = undefined;
    fetchStatus = 200;
    const [result] = await scheduler.syncOrg(orgId);
    expect(result).toMatchObject({ upserted: 1, archived: 1 });

    const beta = await owner.asset.findUnique({
      where: {
        orgId_externalKey: {
          orgId,
          externalKey: `gcp:${PROJECT}:gce:us-central1-a:web-beta`,
        },
      },
    });
    expect(beta?.archivedAt).not.toBeNull();
  });

  it('GET-by-id on an org miss is 404, never 500 or empty-200', async () => {
    const owned = await owner.asset.findFirst({
      where: { orgId, source: 'gcp', archivedAt: null },
    });
    expect(owned).toBeTruthy();

    await expect(assets.get(orgBId, owned!.id)).rejects.toBeInstanceOf(NotFoundException);

    const fromB = await prisma.withOrg(orgBId, (tx) => tx.asset.findUnique({ where: { id: owned!.id } }));
    expect(fromB).toBeNull();
  });

  it("does not leak assets to a second org and does not touch that org's integrations", async () => {
    const other = await owner.integration.create({
      data: {
        orgId: orgBId,
        provider: 'gcp',
        displayName: 'org-b-gcp',
        config: { projectId: PROJECT, resourceTypes: ['gce_instance'] },
        credentialRef: 'env:GCP_CLIENT_EMAIL',
      },
    });
    await owner.asset.create({
      data: {
        orgId: orgBId,
        kind: 'cloud_resource',
        externalKey: `gcp:${PROJECT}:gce:us-central1-a:web-secret`,
        name: 'secret',
        source: 'gcp',
        integrationId: other.id,
      },
    });

    instanceNames = ['web-alpha'];
    nextToken = undefined;
    fetchStatus = 200;
    await scheduler.syncOrg(orgId);

    const fromB = await prisma.withOrg(orgBId, (tx) => tx.asset.findMany());
    expect(fromB.map((a) => a.externalKey)).toEqual([`gcp:${PROJECT}:gce:us-central1-a:web-secret`]);
    expect(fromB.some((a) => a.externalKey.endsWith(':web-alpha'))).toBe(false);

    const bAfter = await owner.integration.findUnique({ where: { id: other.id } });
    expect(bAfter?.lastSyncAt).toBeNull();
    expect(bAfter?.lastSyncError).toBeNull();
  });

  it('does not archiveStale when listing is truncated at the page cap', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const keep = await owner.asset.create({
      data: {
        orgId,
        kind: 'cloud_resource',
        externalKey: `gcp:${PROJECT}:gce:us-central1-a:web-keep`,
        name: 'keep',
        source: 'gcp',
        integrationId: first!.id,
      },
    });

    let page = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const parsed = new URL(String(url));
        if (parsed.hostname === 'oauth2.googleapis.com') {
          return new Response(JSON.stringify({ access_token: 'ya29.test' }), { status: 200 });
        }
        if (parsed.pathname.includes('/aggregated/instances')) {
          page += 1;
          const names = Array.from({ length: GCP_PER_PAGE }, (_, i) => `web-t-${page}-${i}`);
          const token = page <= GCP_MAX_PAGES ? `more-${page}` : undefined;
          const instances = names.map((name) => ({
            name,
            zone: `https://www.googleapis.com/compute/v1/projects/${PROJECT}/zones/us-central1-a`,
            status: 'RUNNING',
          }));
          return new Response(
            JSON.stringify({
              items: { 'zones/us-central1-a': { instances } },
              nextPageToken: token,
            }),
            { status: 200 },
          );
        }
        return new Response('unexpected', { status: 500 });
      }),
    );

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/truncated/);
    expect(result.archived).toBe(0);

    const kept = await owner.asset.findUnique({ where: { id: keep.id } });
    expect(kept?.archivedAt).toBeNull();

    const integration = await owner.integration.findUnique({ where: { id: first!.id } });
    expect(integration?.lastSyncError).toMatch(/truncated/);
  });

  it('does not archive inventory when GCP_* credentials are missing', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const before = await owner.asset.findMany({
      where: { orgId, source: 'gcp', integrationId: first!.id, archivedAt: null },
    });
    expect(before.length).toBeGreaterThan(0);

    const email = process.env.GCP_CLIENT_EMAIL;
    delete process.env.GCP_CLIENT_EMAIL;

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/cannot be used|fails closed/);
    expect(result.archived).toBe(0);

    const after = await owner.asset.findMany({
      where: { orgId, source: 'gcp', integrationId: first!.id, archivedAt: null },
    });
    expect(after.length).toBe(before.length);

    process.env.GCP_CLIENT_EMAIL = email;
  });

  it('refuses a tenant-writable endpoint without wiping inventory or sending keys', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const bad = await owner.integration.create({
      data: {
        orgId,
        provider: 'gcp',
        displayName: 'exfil-endpoint',
        config: { projectId: PROJECT, endpoint: 'https://evil.example' },
        credentialRef: 'env:GCP_CLIENT_EMAIL',
      },
    });

    const result = await scheduler.syncIntegration(bad);
    expect(result.error).toMatch(/tenant-writable GCP endpoint/);
    expect(result.archived).toBe(0);
    expect(result.error).not.toMatch(/evil\.example/);

    const row = await owner.integration.findUnique({ where: { id: bad.id } });
    expect(row?.lastSyncError).toMatch(/tenant-writable GCP endpoint/);

    const kept = await owner.asset.findMany({
      where: { orgId, source: 'gcp', integrationId: first!.id, archivedAt: null },
    });
    expect(kept.length).toBeGreaterThan(0);
  });
});

import { NotFoundException } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { AZURE_MAX_PAGES, AZURE_PER_PAGE, AzureConnector } from './azure.connector';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';

const SUB = '11111111-1111-1111-1111-111111111111';
const TENANT = '22222222-2222-2222-2222-222222222222';
const CLIENT = '33333333-3333-3333-3333-333333333333';
const RG = 'rg-prod';

/**
 * The discovery loop against the real database: integration → Azure (stubbed)
 * → asset upserts → stale archival on the next sync. Runs as ctem_app, so RLS
 * applies exactly as in deployment. HTTP is mocked — no live Azure.
 */
describe('Azure discovery (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let assets: AssetsService;
  let scheduler: DiscoverySchedulerService;
  let orgId: string;
  let orgBId: string;
  const events: Array<{ subject: string }> = [];
  let vmNames: string[] = [];
  let continuation: string | undefined;
  let fetchStatus = 200;

  function vmsJson(): string {
    const value = vmNames.map((name) => ({
      name,
      id: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachines/${name}`,
      location: 'eastus',
      properties: { provisioningState: 'Succeeded' },
    }));
    return JSON.stringify({
      value,
      ...(continuation ? { nextLink: continuation } : {}),
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
        provider: 'azure',
        displayName: 'discovery-int-test',
        config: { subscriptionId: SUB, resourceTypes: ['virtual_machine'] },
        credentialRef: 'env:AZURE_CLIENT_ID',
      },
    });
    process.env.AZURE_TENANT_ID = TENANT;
    process.env.AZURE_CLIENT_ID = CLIENT;
    process.env.AZURE_CLIENT_SECRET = 'super-secret';

    const bus = {
      publish: vi.fn(async (subject: string) => {
        events.push({ subject });
      }),
    } as unknown as EventBus;

    const registry = new ConnectorRegistry();
    registry.register(new AzureConnector());
    assets = new AssetsService(prisma, bus);
    scheduler = new DiscoverySchedulerService(prisma, registry, assets);

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const parsed = new URL(String(url));
        if (parsed.hostname === 'login.microsoftonline.com') {
          return new Response(JSON.stringify({ access_token: 'eyJhbGciOiJSUzI1NiJ9.test' }), { status: 200 });
        }
        if (fetchStatus !== 200) return new Response('boom', { status: fetchStatus });
        if (parsed.pathname.includes('/virtualMachines')) {
          return new Response(vmsJson(), { status: 200 });
        }
        return new Response('unexpected', { status: 500 });
      }),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    delete process.env.AZURE_TENANT_ID;
    delete process.env.AZURE_CLIENT_ID;
    delete process.env.AZURE_CLIENT_SECRET;
    await owner.organization.deleteMany({ where: { id: { in: [orgId, orgBId] } } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('inventories Azure resources as cloud_resource and publishes discovery events', async () => {
    vmNames = ['web-alpha', 'web-beta'];
    continuation = undefined;
    fetchStatus = 200;
    const results = await scheduler.syncOrg(orgId);
    expect(results).toEqual([
      expect.objectContaining({ provider: 'azure', upserted: 2, archived: 0, error: null }),
    ]);

    const rows = await owner.asset.findMany({ where: { orgId }, orderBy: { name: 'asc' } });
    expect(rows.map((a) => a.externalKey)).toEqual([
      `azure:${SUB}:vm:${RG}:web-alpha`,
      `azure:${SUB}:vm:${RG}:web-beta`,
    ]);
    expect(rows.every((a) => a.kind === 'cloud_resource')).toBe(true);
    expect(rows.every((a) => a.source === 'azure')).toBe(true);
    expect(events.filter((e) => e.subject === 'ctem.asset.discovered')).toHaveLength(2);

    const integration = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    expect(rows.every((a) => a.integrationId === integration?.id)).toBe(true);
    expect(integration?.lastSyncAt).not.toBeNull();
    expect(integration?.lastSyncError).toBeNull();
  });

  it('archives assets that stop appearing instead of deleting them', async () => {
    vmNames = ['web-alpha'];
    continuation = undefined;
    fetchStatus = 200;
    const [result] = await scheduler.syncOrg(orgId);
    expect(result).toMatchObject({ upserted: 1, archived: 1 });

    const beta = await owner.asset.findUnique({
      where: {
        orgId_externalKey: {
          orgId,
          externalKey: `azure:${SUB}:vm:${RG}:web-beta`,
        },
      },
    });
    expect(beta?.archivedAt).not.toBeNull();
  });

  it('GET-by-id on an org miss is 404, never 500 or empty-200', async () => {
    const owned = await owner.asset.findFirst({
      where: { orgId, source: 'azure', archivedAt: null },
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
        provider: 'azure',
        displayName: 'org-b-azure',
        config: { subscriptionId: SUB, resourceTypes: ['virtual_machine'] },
        credentialRef: 'env:AZURE_CLIENT_ID',
      },
    });
    await owner.asset.create({
      data: {
        orgId: orgBId,
        kind: 'cloud_resource',
        externalKey: `azure:${SUB}:vm:${RG}:web-secret`,
        name: 'secret',
        source: 'azure',
        integrationId: other.id,
      },
    });

    vmNames = ['web-alpha'];
    continuation = undefined;
    fetchStatus = 200;
    await scheduler.syncOrg(orgId);

    const fromB = await prisma.withOrg(orgBId, (tx) => tx.asset.findMany());
    expect(fromB.map((a) => a.externalKey)).toEqual([`azure:${SUB}:vm:${RG}:web-secret`]);
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
        externalKey: `azure:${SUB}:vm:${RG}:web-keep`,
        name: 'keep',
        source: 'azure',
        integrationId: first!.id,
      },
    });

    let page = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const parsed = new URL(String(url));
        if (parsed.hostname === 'login.microsoftonline.com') {
          return new Response(JSON.stringify({ access_token: 'eyJhbGciOiJSUzI1NiJ9.test' }), { status: 200 });
        }
        if (parsed.pathname.includes('/virtualMachines')) {
          page += 1;
          const names = Array.from({ length: AZURE_PER_PAGE }, (_, i) => `web-t-${page}-${i}`);
          const link =
            page <= AZURE_MAX_PAGES
              ? `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01&$skiptoken=more-${page}`
              : undefined;
          const value = names.map((name) => ({
            name,
            id: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachines/${name}`,
            location: 'eastus',
            properties: { provisioningState: 'Succeeded' },
          }));
          return new Response(JSON.stringify({ value, nextLink: link }), { status: 200 });
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

  it('does not archive inventory when AZURE_* credentials are missing', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const before = await owner.asset.findMany({
      where: { orgId, source: 'azure', integrationId: first!.id, archivedAt: null },
    });
    expect(before.length).toBeGreaterThan(0);

    const clientId = process.env.AZURE_CLIENT_ID;
    delete process.env.AZURE_CLIENT_ID;

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/cannot be used|fails closed/);
    expect(result.archived).toBe(0);

    const after = await owner.asset.findMany({
      where: { orgId, source: 'azure', integrationId: first!.id, archivedAt: null },
    });
    expect(after.length).toBe(before.length);

    process.env.AZURE_CLIENT_ID = clientId;
  });

  it('refuses a tenant-writable endpoint without wiping inventory or sending keys', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const bad = await owner.integration.create({
      data: {
        orgId,
        provider: 'azure',
        displayName: 'exfil-endpoint',
        config: { subscriptionId: SUB, endpoint: 'https://evil.example' },
        credentialRef: 'env:AZURE_CLIENT_ID',
      },
    });

    const result = await scheduler.syncIntegration(bad);
    expect(result.error).toMatch(/tenant-writable Azure endpoint/);
    expect(result.archived).toBe(0);
    expect(result.error).not.toMatch(/evil\.example/);

    const row = await owner.integration.findUnique({ where: { id: bad.id } });
    expect(row?.lastSyncError).toMatch(/tenant-writable Azure endpoint/);

    const kept = await owner.asset.findMany({
      where: { orgId, source: 'azure', integrationId: first!.id, archivedAt: null },
    });
    expect(kept.length).toBeGreaterThan(0);
  });
});

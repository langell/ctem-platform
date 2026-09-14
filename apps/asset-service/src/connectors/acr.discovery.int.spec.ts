import { NotFoundException } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { ACR_MAX_PAGES, ACR_PER_PAGE, AcrConnector } from './acr.connector';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';

const SUB = '11111111-1111-1111-1111-111111111111';
const TENANT = '22222222-2222-2222-2222-222222222222';
const CLIENT = '33333333-3333-3333-3333-333333333333';
const RG = 'rg-prod';
const REGISTRY = 'acmeprod';
const LOGIN = 'acmeprod.azurecr.io';
const DIGEST_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

/**
 * The discovery loop against the real database: integration → ACR (stubbed
 * ARM registries + /acr/v1 catalog/manifests) → asset upserts → stale
 * archival on the next sync. Runs as ctem_app, so RLS applies exactly as in
 * deployment. HTTP is mocked — no live Azure.
 */
describe('ACR discovery (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let assets: AssetsService;
  let scheduler: DiscoverySchedulerService;
  let orgId: string;
  let orgBId: string;
  const events: Array<{ subject: string }> = [];
  let repositoryNames: string[] = [];
  let imagesByRepo: Record<string, Array<{ digest: string; tags: string[] }>> = {};
  let catalogNext: string | undefined;
  let fetchStatus = 200;

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    orgId = (await createOrg(owner)).id;
    orgBId = (await createOrg(owner)).id;

    await owner.integration.create({
      data: {
        orgId,
        provider: 'acr',
        displayName: 'discovery-int-test',
        config: { subscriptionId: SUB },
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
    registry.register(new AcrConnector());
    assets = new AssetsService(prisma, bus);
    scheduler = new DiscoverySchedulerService(prisma, registry, assets);

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const parsed = new URL(String(url));
        expect(parsed.protocol).toBe('https:');
        if (parsed.hostname === 'login.microsoftonline.com') {
          return new Response(JSON.stringify({ access_token: 'eyJhbGciOiJSUzI1NiJ9.test' }), {
            status: 200,
          });
        }
        if (fetchStatus !== 200) return new Response('boom', { status: fetchStatus });
        if (parsed.hostname === 'management.azure.com') {
          expect(parsed.pathname).toContain('/Microsoft.ContainerRegistry/registries');
          return new Response(
            JSON.stringify({
              value: [
                {
                  name: REGISTRY,
                  id: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.ContainerRegistry/registries/${REGISTRY}`,
                  location: 'eastus',
                  properties: { loginServer: LOGIN },
                },
              ],
            }),
            { status: 200 },
          );
        }
        expect(parsed.hostname).toBe(LOGIN);
        expect(parsed.pathname).not.toMatch(/\/blobs?\//);
        expect(parsed.pathname).not.toMatch(/\/v2\//);
        if (parsed.pathname === '/oauth2/exchange') {
          return new Response(JSON.stringify({ refresh_token: 'acr-refresh' }), { status: 200 });
        }
        if (parsed.pathname === '/oauth2/token') {
          return new Response(JSON.stringify({ access_token: 'acr-access' }), { status: 200 });
        }
        if (parsed.pathname === '/acr/v1/_catalog') {
          const headers = new Headers({ 'content-type': 'application/json' });
          if (catalogNext) headers.set('link', `<${catalogNext}>; rel="next"`);
          return new Response(JSON.stringify({ repositories: repositoryNames }), {
            status: 200,
            headers,
          });
        }
        if (parsed.pathname.includes('/_manifests')) {
          const parts = parsed.pathname.split('/').filter(Boolean);
          const name = parts
            .slice(2, -1)
            .map((p) => decodeURIComponent(p))
            .join('/');
          const images = imagesByRepo[name] ?? [];
          return new Response(
            JSON.stringify({
              manifests: images.map((img) => ({ digest: img.digest, tags: img.tags })),
            }),
            { status: 200 },
          );
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

  it('inventories ACR images as container_image assets keyed by digest', async () => {
    repositoryNames = ['payments-api', 'worker'];
    imagesByRepo = {
      'payments-api': [{ digest: DIGEST_A, tags: ['latest', 'v1'] }],
      worker: [{ digest: DIGEST_B, tags: ['stable'] }],
    };
    catalogNext = undefined;
    fetchStatus = 200;
    const results = await scheduler.syncOrg(orgId);
    expect(results).toEqual([
      expect.objectContaining({ provider: 'acr', upserted: 2, archived: 0, error: null }),
    ]);

    const rows = await owner.asset.findMany({ where: { orgId }, orderBy: { name: 'asc' } });
    expect(rows.map((a) => a.externalKey)).toEqual([
      `acr:${SUB}/${RG}/${REGISTRY}/payments-api@${DIGEST_A}`,
      `acr:${SUB}/${RG}/${REGISTRY}/worker@${DIGEST_B}`,
    ]);
    expect(rows.every((a) => a.kind === 'container_image')).toBe(true);
    expect(rows.every((a) => a.source === 'acr')).toBe(true);
    expect(rows.every((a) => a.kind !== 'repository')).toBe(true);
    expect(events.filter((e) => e.subject === 'ctem.asset.discovered')).toHaveLength(2);

    const integration = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    expect(rows.every((a) => a.integrationId === integration?.id)).toBe(true);
    expect(integration?.lastSyncAt).not.toBeNull();
    expect(integration?.lastSyncError).toBeNull();
  });

  it('archives assets that stop appearing instead of deleting them', async () => {
    repositoryNames = ['payments-api'];
    imagesByRepo = {
      'payments-api': [{ digest: DIGEST_A, tags: ['latest'] }],
    };
    catalogNext = undefined;
    fetchStatus = 200;
    const [result] = await scheduler.syncOrg(orgId);
    expect(result).toMatchObject({ upserted: 1, archived: 1 });

    const worker = await owner.asset.findUnique({
      where: {
        orgId_externalKey: {
          orgId,
          externalKey: `acr:${SUB}/${RG}/${REGISTRY}/worker@${DIGEST_B}`,
        },
      },
    });
    expect(worker?.archivedAt).not.toBeNull();
  });

  it('GET-by-id on an org miss is 404, never 500 or empty-200', async () => {
    const owned = await owner.asset.findFirst({
      where: { orgId, source: 'acr', archivedAt: null },
    });
    expect(owned).toBeTruthy();

    await expect(assets.get(orgBId, owned!.id)).rejects.toBeInstanceOf(NotFoundException);

    const fromB = await prisma.withOrg(orgBId, (tx) =>
      tx.asset.findUnique({ where: { id: owned!.id } }),
    );
    expect(fromB).toBeNull();
  });

  it("does not leak assets to a second org and does not touch that org's integrations", async () => {
    const other = await owner.integration.create({
      data: {
        orgId: orgBId,
        provider: 'acr',
        displayName: 'org-b-acr',
        config: { subscriptionId: SUB },
        credentialRef: 'env:AZURE_CLIENT_ID',
      },
    });
    await owner.asset.create({
      data: {
        orgId: orgBId,
        kind: 'container_image',
        externalKey: `acr:${SUB}/${RG}/${REGISTRY}/secret@${DIGEST_A}`,
        name: 'secret',
        source: 'acr',
        integrationId: other.id,
      },
    });

    repositoryNames = ['payments-api'];
    imagesByRepo = {
      'payments-api': [{ digest: DIGEST_A, tags: ['latest'] }],
    };
    catalogNext = undefined;
    fetchStatus = 200;
    await scheduler.syncOrg(orgId);

    const fromB = await prisma.withOrg(orgBId, (tx) => tx.asset.findMany());
    expect(fromB.map((a) => a.externalKey)).toEqual([
      `acr:${SUB}/${RG}/${REGISTRY}/secret@${DIGEST_A}`,
    ]);
    expect(fromB.some((a) => a.externalKey.includes('payments-api'))).toBe(false);

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
        kind: 'container_image',
        externalKey: `acr:${SUB}/${RG}/${REGISTRY}/keep@${DIGEST_B}`,
        name: 'keep',
        source: 'acr',
        integrationId: first!.id,
      },
    });

    let page = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const parsed = new URL(String(url));
        if (parsed.hostname === 'login.microsoftonline.com') {
          return new Response(JSON.stringify({ access_token: 'eyJhbGciOiJSUzI1NiJ9.test' }), {
            status: 200,
          });
        }
        if (parsed.hostname === 'management.azure.com') {
          return new Response(
            JSON.stringify({
              value: [
                {
                  name: REGISTRY,
                  id: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.ContainerRegistry/registries/${REGISTRY}`,
                  properties: { loginServer: LOGIN },
                },
              ],
            }),
            { status: 200 },
          );
        }
        expect(parsed.hostname).toBe(LOGIN);
        expect(parsed.pathname).not.toMatch(/\/blobs?\//);
        if (parsed.pathname === '/oauth2/exchange') {
          return new Response(JSON.stringify({ refresh_token: 'acr-refresh' }), { status: 200 });
        }
        if (parsed.pathname === '/oauth2/token') {
          return new Response(JSON.stringify({ access_token: 'acr-access' }), { status: 200 });
        }
        if (parsed.pathname.includes('/_manifests')) {
          return new Response(JSON.stringify({ manifests: [] }), { status: 200 });
        }
        if (parsed.pathname === '/acr/v1/_catalog') {
          page += 1;
          const names = Array.from({ length: ACR_PER_PAGE }, (_, i) => `img-t-${page}-${i}`);
          const next =
            page <= ACR_MAX_PAGES ? `/acr/v1/_catalog?last=more-${page}&n=100` : undefined;
          const headers = new Headers({ 'content-type': 'application/json' });
          if (next) headers.set('link', `<${next}>; rel="next"`);
          return new Response(JSON.stringify({ repositories: names }), { status: 200, headers });
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
      where: { orgId, source: 'acr', integrationId: first!.id, archivedAt: null },
    });
    expect(before.length).toBeGreaterThan(0);

    const secret = process.env.AZURE_CLIENT_SECRET;
    delete process.env.AZURE_CLIENT_SECRET;

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/cannot be used|fails closed|env:AZURE_\*/);
    expect(result.archived).toBe(0);

    const after = await owner.asset.findMany({
      where: { orgId, source: 'acr', integrationId: first!.id, archivedAt: null },
    });
    expect(after.length).toBe(before.length);

    process.env.AZURE_CLIENT_SECRET = secret;
  });

  it('refuses a tenant-writable endpoint without wiping inventory or sending keys', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const bad = await owner.integration.create({
      data: {
        orgId,
        provider: 'acr',
        displayName: 'exfil-endpoint',
        config: {
          subscriptionId: SUB,
          loginServer: 'acmeprod.azurecr.io',
          registryUrl: 'https://acmeprod.azurecr.io',
          endpoint: 'https://evil.example',
        },
        credentialRef: 'env:AZURE_CLIENT_ID',
      },
    });

    const result = await scheduler.syncIntegration(bad);
    expect(result.error).toMatch(/tenant-writable ACR endpoint/);
    expect(result.archived).toBe(0);
    expect(result.error).not.toMatch(/evil\.example/);

    const row = await owner.integration.findUnique({ where: { id: bad.id } });
    expect(row?.lastSyncError).toMatch(/tenant-writable ACR endpoint/);

    const kept = await owner.asset.findMany({
      where: { orgId, source: 'acr', integrationId: first!.id, archivedAt: null },
    });
    expect(kept.length).toBeGreaterThan(0);
  });
});

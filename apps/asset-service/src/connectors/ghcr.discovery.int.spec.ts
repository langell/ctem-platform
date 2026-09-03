import { NotFoundException } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { GHCR_MAX_PAGES, GHCR_PER_PAGE, GhcrConnector } from './ghcr.connector';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';

const DIGEST_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

/**
 * The discovery loop against the real database: integration → GHCR (stubbed
 * GitHub Packages REST) → asset upserts → stale archival on the next sync.
 * Runs as ctem_app, so RLS applies exactly as in deployment. HTTP is mocked
 * — no live GitHub.
 */
describe('GHCR discovery (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let assets: AssetsService;
  let scheduler: DiscoverySchedulerService;
  let orgId: string;
  let orgBId: string;
  const events: Array<{ subject: string }> = [];
  let packageNames: string[] = [];
  let versionsByPackage: Record<string, Array<{ name: string; tags: string[] }>> = {};
  let packageNext: string | undefined;
  let fetchStatus = 200;

  function packagesJson(): string {
    return JSON.stringify(
      packageNames.map((name) => ({
        name,
        package_type: 'container',
        visibility: 'private',
        html_url: `https://github.com/orgs/acme/packages/container/package/${name}`,
        owner: { login: 'acme' },
      })),
    );
  }

  function versionsJson(name: string): string {
    const versions = versionsByPackage[name] ?? [];
    return JSON.stringify(
      versions.map((v) => ({
        name: v.name,
        metadata: { package_type: 'container', container: { tags: v.tags } },
      })),
    );
  }

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    orgId = (await createOrg(owner)).id;
    orgBId = (await createOrg(owner)).id;

    await owner.integration.create({
      data: {
        orgId,
        provider: 'ghcr',
        displayName: 'discovery-int-test',
        config: { owner: 'acme', ownerType: 'org' },
        credentialRef: 'env:GITHUB_TOKEN',
      },
    });
    process.env.GITHUB_TOKEN = 'ghp_int_test';

    const bus = {
      publish: vi.fn(async (subject: string) => {
        events.push({ subject });
      }),
    } as unknown as EventBus;

    const registry = new ConnectorRegistry();
    registry.register(new GhcrConnector());
    assets = new AssetsService(prisma, bus);
    scheduler = new DiscoverySchedulerService(prisma, registry, assets);

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const parsed = new URL(String(url));
        expect(parsed.hostname).toBe('api.github.com');
        expect(parsed.hostname).not.toBe('ghcr.io');
        if (fetchStatus !== 200) return new Response('boom', { status: fetchStatus });
        if (parsed.pathname.includes('/versions')) {
          const match = parsed.pathname.match(/\/packages\/container\/([^/]+)\/versions$/);
          const name = decodeURIComponent(match?.[1] ?? '');
          return new Response(versionsJson(name), { status: 200 });
        }
        if (parsed.pathname.endsWith('/packages')) {
          return new Response(packagesJson(), {
            status: 200,
            headers: packageNext ? { link: `<${packageNext}>; rel="next"` } : {},
          });
        }
        return new Response('unexpected', { status: 500 });
      }),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    delete process.env.GITHUB_TOKEN;
    await owner.organization.deleteMany({ where: { id: { in: [orgId, orgBId] } } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('inventories GHCR packages as container_image assets keyed by digest', async () => {
    packageNames = ['payments-api', 'worker'];
    versionsByPackage = {
      'payments-api': [{ name: DIGEST_A, tags: ['latest', 'v1'] }],
      worker: [{ name: DIGEST_B, tags: ['stable'] }],
    };
    packageNext = undefined;
    fetchStatus = 200;
    const results = await scheduler.syncOrg(orgId);
    expect(results).toEqual([
      expect.objectContaining({ provider: 'ghcr', upserted: 2, archived: 0, error: null }),
    ]);

    const rows = await owner.asset.findMany({ where: { orgId }, orderBy: { name: 'asc' } });
    expect(rows.map((a) => a.externalKey)).toEqual([
      `ghcr:acme/payments-api@${DIGEST_A}`,
      `ghcr:acme/worker@${DIGEST_B}`,
    ]);
    expect(rows.every((a) => a.kind === 'container_image')).toBe(true);
    expect(rows.every((a) => a.source === 'ghcr')).toBe(true);
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
    packageNames = ['payments-api'];
    versionsByPackage = {
      'payments-api': [{ name: DIGEST_A, tags: ['latest'] }],
    };
    packageNext = undefined;
    fetchStatus = 200;
    const [result] = await scheduler.syncOrg(orgId);
    expect(result).toMatchObject({ upserted: 1, archived: 1 });

    const worker = await owner.asset.findUnique({
      where: {
        orgId_externalKey: {
          orgId,
          externalKey: `ghcr:acme/worker@${DIGEST_B}`,
        },
      },
    });
    expect(worker?.archivedAt).not.toBeNull();
  });

  it('GET-by-id on an org miss is 404, never 500 or empty-200', async () => {
    const owned = await owner.asset.findFirst({
      where: { orgId, source: 'ghcr', archivedAt: null },
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
        provider: 'ghcr',
        displayName: 'org-b-ghcr',
        config: { owner: 'acme', ownerType: 'org' },
        credentialRef: 'env:GITHUB_TOKEN',
      },
    });
    await owner.asset.create({
      data: {
        orgId: orgBId,
        kind: 'container_image',
        externalKey: `ghcr:acme/secret@${DIGEST_A}`,
        name: 'secret',
        source: 'ghcr',
        integrationId: other.id,
      },
    });

    packageNames = ['payments-api'];
    versionsByPackage = {
      'payments-api': [{ name: DIGEST_A, tags: ['latest'] }],
    };
    packageNext = undefined;
    fetchStatus = 200;
    await scheduler.syncOrg(orgId);

    const fromB = await prisma.withOrg(orgBId, (tx) => tx.asset.findMany());
    expect(fromB.map((a) => a.externalKey)).toEqual([`ghcr:acme/secret@${DIGEST_A}`]);
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
        externalKey: `ghcr:acme/keep@${DIGEST_B}`,
        name: 'keep',
        source: 'ghcr',
        integrationId: first!.id,
      },
    });

    let page = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const parsed = new URL(String(url));
        expect(parsed.hostname).toBe('api.github.com');
        if (parsed.pathname.includes('/versions')) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        if (parsed.pathname.endsWith('/packages')) {
          page += 1;
          const names = Array.from({ length: GHCR_PER_PAGE }, (_, i) => `img-t-${page}-${i}`);
          const next =
            page <= GHCR_MAX_PAGES
              ? `https://api.github.com/orgs/acme/packages?package_type=container&page=${page + 1}`
              : undefined;
          const body = names.map((name) => ({
            name,
            package_type: 'container',
            visibility: 'private',
            owner: { login: 'acme' },
          }));
          return new Response(JSON.stringify(body), {
            status: 200,
            headers: next ? { link: `<${next}>; rel="next"` } : {},
          });
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

  it('does not archive inventory when GITHUB_* credentials are missing', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const before = await owner.asset.findMany({
      where: { orgId, source: 'ghcr', integrationId: first!.id, archivedAt: null },
    });
    expect(before.length).toBeGreaterThan(0);

    const token = process.env.GITHUB_TOKEN;
    delete process.env.GITHUB_TOKEN;

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/cannot be used|fails closed|env:GITHUB_\*/);
    expect(result.archived).toBe(0);

    const after = await owner.asset.findMany({
      where: { orgId, source: 'ghcr', integrationId: first!.id, archivedAt: null },
    });
    expect(after.length).toBe(before.length);

    process.env.GITHUB_TOKEN = token;
  });

  it('refuses a tenant-writable endpoint without wiping inventory or sending keys', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const bad = await owner.integration.create({
      data: {
        orgId,
        provider: 'ghcr',
        displayName: 'exfil-endpoint',
        config: { owner: 'acme', ownerType: 'org', registryUrl: 'https://ghcr.io', endpoint: 'https://evil.example' },
        credentialRef: 'env:GITHUB_TOKEN',
      },
    });

    const result = await scheduler.syncIntegration(bad);
    expect(result.error).toMatch(/tenant-writable GHCR endpoint/);
    expect(result.archived).toBe(0);
    expect(result.error).not.toMatch(/evil\.example/);

    const row = await owner.integration.findUnique({ where: { id: bad.id } });
    expect(row?.lastSyncError).toMatch(/tenant-writable GHCR endpoint/);

    const kept = await owner.asset.findMany({
      where: { orgId, source: 'ghcr', integrationId: first!.id, archivedAt: null },
    });
    expect(kept.length).toBeGreaterThan(0);
  });
});

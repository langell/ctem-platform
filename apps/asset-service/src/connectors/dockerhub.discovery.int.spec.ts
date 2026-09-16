import { NotFoundException } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { DOCKERHUB_MAX_PAGES, DOCKERHUB_PER_PAGE, DockerhubConnector } from './dockerhub.connector';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';

const DIGEST_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

/**
 * The discovery loop against the real database: integration → Docker Hub
 * (stubbed Hub API) → asset upserts → stale archival on the next sync.
 * Runs as ctem_app, so RLS applies exactly as in deployment. HTTP is mocked
 * — no live Docker Hub.
 */
describe('Docker Hub discovery (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let assets: AssetsService;
  let scheduler: DiscoverySchedulerService;
  let orgId: string;
  let orgBId: string;
  const events: Array<{ subject: string }> = [];
  let repositoryNames: string[] = [];
  let tagsByRepo: Record<string, Array<{ name: string; digest: string }>> = {};
  let repoNext: string | undefined;
  let fetchStatus = 200;

  function repositoriesJson(): string {
    return JSON.stringify({
      count: repositoryNames.length,
      next: repoNext ?? null,
      previous: null,
      results: repositoryNames.map((name) => ({
        name,
        namespace: 'acme',
        repository_type: 'image',
        is_private: true,
      })),
    });
  }

  function tagsJson(name: string): string {
    const tags = tagsByRepo[name] ?? [];
    return JSON.stringify({
      count: tags.length,
      next: null,
      previous: null,
      results: tags.map((t) => ({
        name: t.name,
        digest: t.digest,
        images: [{ architecture: 'amd64', os: 'linux', digest: t.digest }],
      })),
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
        provider: 'dockerhub',
        displayName: 'discovery-int-test',
        config: { namespace: 'acme' },
        credentialRef: 'env:DOCKERHUB_TOKEN',
      },
    });
    process.env.DOCKERHUB_USERNAME = 'acme';
    process.env.DOCKERHUB_TOKEN = 'dckr_pat_int_test';

    const bus = {
      publish: vi.fn(async (subject: string) => {
        events.push({ subject });
      }),
    } as unknown as EventBus;

    const registry = new ConnectorRegistry();
    registry.register(new DockerhubConnector());
    assets = new AssetsService(prisma, bus);
    scheduler = new DiscoverySchedulerService(prisma, registry, assets);

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const parsed = new URL(String(url));
        expect(parsed.hostname).toBe('hub.docker.com');
        expect(parsed.hostname).not.toBe('registry-1.docker.io');
        expect(parsed.hostname).not.toBe('index.docker.io');
        const path = parsed.pathname.replace(/\/+$/, '') || '/';
        if (path === '/v2/users/login') {
          return new Response(JSON.stringify({ token: 'jwt-int-test' }), { status: 200 });
        }
        if (fetchStatus !== 200) return new Response('boom', { status: fetchStatus });
        if (path.endsWith('/tags')) {
          const match = path.match(/\/v2\/repositories\/[^/]+\/([^/]+)\/tags$/);
          const name = decodeURIComponent(match?.[1] ?? '');
          return new Response(tagsJson(name), { status: 200 });
        }
        if (path.startsWith('/v2/repositories/')) {
          return new Response(repositoriesJson(), { status: 200 });
        }
        return new Response('unexpected', { status: 500 });
      }),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    delete process.env.DOCKERHUB_USERNAME;
    delete process.env.DOCKERHUB_TOKEN;
    await owner.organization.deleteMany({ where: { id: { in: [orgId, orgBId] } } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('inventories Docker Hub repositories as container_image assets keyed by digest', async () => {
    repositoryNames = ['payments-api', 'worker'];
    tagsByRepo = {
      'payments-api': [{ name: 'latest', digest: DIGEST_A }],
      worker: [{ name: 'stable', digest: DIGEST_B }],
    };
    repoNext = undefined;
    fetchStatus = 200;
    const results = await scheduler.syncOrg(orgId);
    expect(results).toEqual([
      expect.objectContaining({ provider: 'dockerhub', upserted: 2, archived: 0, error: null }),
    ]);

    const rows = await owner.asset.findMany({ where: { orgId }, orderBy: { name: 'asc' } });
    expect(rows.map((a) => a.externalKey)).toEqual([
      `dockerhub:acme/payments-api@${DIGEST_A}`,
      `dockerhub:acme/worker@${DIGEST_B}`,
    ]);
    expect(rows.every((a) => a.kind === 'container_image')).toBe(true);
    expect(rows.every((a) => a.source === 'dockerhub')).toBe(true);
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
    tagsByRepo = {
      'payments-api': [{ name: 'latest', digest: DIGEST_A }],
    };
    repoNext = undefined;
    fetchStatus = 200;
    const [result] = await scheduler.syncOrg(orgId);
    expect(result).toMatchObject({ upserted: 1, archived: 1 });

    const worker = await owner.asset.findUnique({
      where: {
        orgId_externalKey: {
          orgId,
          externalKey: `dockerhub:acme/worker@${DIGEST_B}`,
        },
      },
    });
    expect(worker?.archivedAt).not.toBeNull();
  });

  it('GET-by-id on an org miss is 404, never 500 or empty-200', async () => {
    const owned = await owner.asset.findFirst({
      where: { orgId, source: 'dockerhub', archivedAt: null },
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
        provider: 'dockerhub',
        displayName: 'org-b-dockerhub',
        config: { namespace: 'acme' },
        credentialRef: 'env:DOCKERHUB_TOKEN',
      },
    });
    await owner.asset.create({
      data: {
        orgId: orgBId,
        kind: 'container_image',
        externalKey: `dockerhub:acme/secret@${DIGEST_A}`,
        name: 'secret',
        source: 'dockerhub',
        integrationId: other.id,
      },
    });

    repositoryNames = ['payments-api'];
    tagsByRepo = {
      'payments-api': [{ name: 'latest', digest: DIGEST_A }],
    };
    repoNext = undefined;
    fetchStatus = 200;
    await scheduler.syncOrg(orgId);

    const fromB = await prisma.withOrg(orgBId, (tx) => tx.asset.findMany());
    expect(fromB.map((a) => a.externalKey)).toEqual([`dockerhub:acme/secret@${DIGEST_A}`]);
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
        externalKey: `dockerhub:acme/keep@${DIGEST_B}`,
        name: 'keep',
        source: 'dockerhub',
        integrationId: first!.id,
      },
    });

    let page = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const parsed = new URL(String(url));
        expect(parsed.hostname).toBe('hub.docker.com');
        const path = parsed.pathname.replace(/\/+$/, '') || '/';
        if (path === '/v2/users/login') {
          return new Response(JSON.stringify({ token: 'jwt-int-test' }), { status: 200 });
        }
        if (path.endsWith('/tags')) {
          return new Response(JSON.stringify({ count: 0, next: null, results: [] }), { status: 200 });
        }
        if (path.startsWith('/v2/repositories/')) {
          page += 1;
          const names = Array.from({ length: DOCKERHUB_PER_PAGE }, (_, i) => `img-t-${page}-${i}`);
          const next =
            page <= DOCKERHUB_MAX_PAGES
              ? `https://hub.docker.com/v2/repositories/acme/?page=${page + 1}`
              : undefined;
          return new Response(
            JSON.stringify({
              count: names.length,
              next: next ?? null,
              results: names.map((name) => ({
                name,
                namespace: 'acme',
                repository_type: 'image',
                is_private: true,
              })),
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

  it('does not archive inventory when DOCKERHUB_* credentials are missing', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const before = await owner.asset.findMany({
      where: { orgId, source: 'dockerhub', integrationId: first!.id, archivedAt: null },
    });
    expect(before.length).toBeGreaterThan(0);

    const token = process.env.DOCKERHUB_TOKEN;
    delete process.env.DOCKERHUB_TOKEN;

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/cannot be used|fails closed|env:DOCKERHUB_\*/);
    expect(result.archived).toBe(0);

    const after = await owner.asset.findMany({
      where: { orgId, source: 'dockerhub', integrationId: first!.id, archivedAt: null },
    });
    expect(after.length).toBe(before.length);

    process.env.DOCKERHUB_TOKEN = token;
  });

  it('refuses a tenant-writable endpoint without wiping inventory or sending keys', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const bad = await owner.integration.create({
      data: {
        orgId,
        provider: 'dockerhub',
        displayName: 'exfil-endpoint',
        config: {
          namespace: 'acme',
          registryUrl: 'https://registry-1.docker.io',
          hubUrl: 'https://hub.docker.com',
          endpoint: 'https://evil.example',
        },
        credentialRef: 'env:DOCKERHUB_TOKEN',
      },
    });

    const result = await scheduler.syncIntegration(bad);
    expect(result.error).toMatch(/tenant-writable Docker Hub endpoint/);
    expect(result.archived).toBe(0);
    expect(result.error).not.toMatch(/evil\.example/);

    const row = await owner.integration.findUnique({ where: { id: bad.id } });
    expect(row?.lastSyncError).toMatch(/tenant-writable Docker Hub endpoint/);

    const kept = await owner.asset.findMany({
      where: { orgId, source: 'dockerhub', integrationId: first!.id, archivedAt: null },
    });
    expect(kept.length).toBeGreaterThan(0);
  });
});

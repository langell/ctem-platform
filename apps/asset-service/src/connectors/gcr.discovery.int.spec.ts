import { NotFoundException } from '@nestjs/common';
import { generateKeyPairSync } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { GCR_MAX_PAGES, GCR_PER_PAGE, GcrConnector } from './gcr.connector';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';

const PROJECT = 'acme-prod';
const LOCATION = 'us-central1';
const DIGEST_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const gcpPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

/**
 * The discovery loop against the real database: integration → GCR (stubbed
 * Artifact Registry ListRepositories / ListDockerImages) → asset upserts →
 * stale archival on the next sync. Runs as ctem_app, so RLS applies exactly
 * as in deployment. HTTP is mocked — no live GCP.
 */
describe('GCR discovery (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let assets: AssetsService;
  let scheduler: DiscoverySchedulerService;
  let orgId: string;
  let orgBId: string;
  const events: Array<{ subject: string }> = [];
  let repositoryNames: string[] = [];
  let imagesByRepo: Record<string, Array<{ image: string; digest: string; tags: string[] }>> = {};
  let repoNext: string | undefined;
  let fetchStatus = 200;

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    orgId = (await createOrg(owner)).id;
    orgBId = (await createOrg(owner)).id;

    await owner.integration.create({
      data: {
        orgId,
        provider: 'gcr',
        displayName: 'discovery-int-test',
        config: { projectId: PROJECT },
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
    registry.register(new GcrConnector());
    assets = new AssetsService(prisma, bus);
    scheduler = new DiscoverySchedulerService(prisma, registry, assets);

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const parsed = new URL(String(url));
        expect(parsed.protocol).toBe('https:');
        if (parsed.hostname === 'oauth2.googleapis.com') {
          return new Response(JSON.stringify({ access_token: 'ya29.test' }), { status: 200 });
        }
        expect(parsed.hostname).toBe('artifactregistry.googleapis.com');
        expect(parsed.hostname).not.toBe('gcr.io');
        expect(parsed.hostname).not.toContain('pkg.dev');
        if (fetchStatus !== 200) return new Response('boom', { status: fetchStatus });
        if (parsed.pathname.includes('/dockerImages')) {
          const parts = parsed.pathname.split('/');
          const repoIdx = parts.indexOf('repositories');
          const name = decodeURIComponent(parts[repoIdx + 1] ?? '');
          const images = imagesByRepo[name] ?? [];
          return new Response(
            JSON.stringify({
              dockerImages: images.map((img) => ({
                name: `projects/${PROJECT}/locations/${LOCATION}/repositories/${name}/dockerImages/${encodeURIComponent(img.image)}@${img.digest}`,
                tags: img.tags,
              })),
            }),
            { status: 200 },
          );
        }
        if (parsed.pathname.endsWith('/repositories')) {
          return new Response(
            JSON.stringify({
              repositories: repositoryNames.map((name) => ({
                name: `projects/${PROJECT}/locations/${LOCATION}/repositories/${name}`,
                format: 'DOCKER',
              })),
              ...(repoNext ? { nextPageToken: repoNext } : {}),
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
    delete process.env.GCP_CLIENT_EMAIL;
    delete process.env.GCP_PRIVATE_KEY;
    await owner.organization.deleteMany({ where: { id: { in: [orgId, orgBId] } } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('inventories GCR images as container_image assets keyed by digest', async () => {
    repositoryNames = ['payments-api', 'worker'];
    imagesByRepo = {
      'payments-api': [{ image: 'web', digest: DIGEST_A, tags: ['latest', 'v1'] }],
      worker: [{ image: 'app', digest: DIGEST_B, tags: ['stable'] }],
    };
    repoNext = undefined;
    fetchStatus = 200;
    const results = await scheduler.syncOrg(orgId);
    expect(results).toEqual([
      expect.objectContaining({ provider: 'gcr', upserted: 2, archived: 0, error: null }),
    ]);

    const rows = await owner.asset.findMany({ where: { orgId }, orderBy: { name: 'asc' } });
    expect(rows.map((a) => a.externalKey)).toEqual([
      `gcr:${PROJECT}/${LOCATION}/payments-api/web@${DIGEST_A}`,
      `gcr:${PROJECT}/${LOCATION}/worker/app@${DIGEST_B}`,
    ]);
    expect(rows.every((a) => a.kind === 'container_image')).toBe(true);
    expect(rows.every((a) => a.source === 'gcr')).toBe(true);
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
      'payments-api': [{ image: 'web', digest: DIGEST_A, tags: ['latest'] }],
    };
    repoNext = undefined;
    fetchStatus = 200;
    const [result] = await scheduler.syncOrg(orgId);
    expect(result).toMatchObject({ upserted: 1, archived: 1 });

    const worker = await owner.asset.findUnique({
      where: {
        orgId_externalKey: {
          orgId,
          externalKey: `gcr:${PROJECT}/${LOCATION}/worker/app@${DIGEST_B}`,
        },
      },
    });
    expect(worker?.archivedAt).not.toBeNull();
  });

  it('GET-by-id on an org miss is 404, never 500 or empty-200', async () => {
    const owned = await owner.asset.findFirst({
      where: { orgId, source: 'gcr', archivedAt: null },
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
        provider: 'gcr',
        displayName: 'org-b-gcr',
        config: { projectId: PROJECT },
        credentialRef: 'env:GCP_CLIENT_EMAIL',
      },
    });
    await owner.asset.create({
      data: {
        orgId: orgBId,
        kind: 'container_image',
        externalKey: `gcr:${PROJECT}/${LOCATION}/secret/app@${DIGEST_A}`,
        name: 'secret',
        source: 'gcr',
        integrationId: other.id,
      },
    });

    repositoryNames = ['payments-api'];
    imagesByRepo = {
      'payments-api': [{ image: 'web', digest: DIGEST_A, tags: ['latest'] }],
    };
    repoNext = undefined;
    fetchStatus = 200;
    await scheduler.syncOrg(orgId);

    const fromB = await prisma.withOrg(orgBId, (tx) => tx.asset.findMany());
    expect(fromB.map((a) => a.externalKey)).toEqual([
      `gcr:${PROJECT}/${LOCATION}/secret/app@${DIGEST_A}`,
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
        externalKey: `gcr:${PROJECT}/${LOCATION}/keep/app@${DIGEST_B}`,
        name: 'keep',
        source: 'gcr',
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
        expect(parsed.hostname).toBe('artifactregistry.googleapis.com');
        expect(parsed.hostname).not.toBe('gcr.io');
        if (parsed.pathname.includes('/dockerImages')) {
          return new Response(JSON.stringify({ dockerImages: [] }), { status: 200 });
        }
        if (parsed.pathname.endsWith('/repositories')) {
          page += 1;
          const names = Array.from({ length: GCR_PER_PAGE }, (_, i) => `img-t-${page}-${i}`);
          const next = page <= GCR_MAX_PAGES ? `more-${page}` : undefined;
          return new Response(
            JSON.stringify({
              repositories: names.map((name) => ({
                name: `projects/${PROJECT}/locations/${LOCATION}/repositories/${name}`,
                format: 'DOCKER',
              })),
              ...(next ? { nextPageToken: next } : {}),
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
      where: { orgId, source: 'gcr', integrationId: first!.id, archivedAt: null },
    });
    expect(before.length).toBeGreaterThan(0);

    const email = process.env.GCP_CLIENT_EMAIL;
    delete process.env.GCP_CLIENT_EMAIL;

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/cannot be used|fails closed|env:GCP_\*/);
    expect(result.archived).toBe(0);

    const after = await owner.asset.findMany({
      where: { orgId, source: 'gcr', integrationId: first!.id, archivedAt: null },
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
        provider: 'gcr',
        displayName: 'exfil-endpoint',
        config: {
          projectId: PROJECT,
          registryUrl: 'https://gcr.io',
          endpoint: 'https://evil.example',
        },
        credentialRef: 'env:GCP_CLIENT_EMAIL',
      },
    });

    const result = await scheduler.syncIntegration(bad);
    expect(result.error).toMatch(/tenant-writable GCR endpoint/);
    expect(result.archived).toBe(0);
    expect(result.error).not.toMatch(/evil\.example/);

    const row = await owner.integration.findUnique({ where: { id: bad.id } });
    expect(row?.lastSyncError).toMatch(/tenant-writable GCR endpoint/);

    const kept = await owner.asset.findMany({
      where: { orgId, source: 'gcr', integrationId: first!.id, archivedAt: null },
    });
    expect(kept.length).toBeGreaterThan(0);
  });
});

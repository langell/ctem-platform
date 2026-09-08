import { NotFoundException } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { ECR_MAX_PAGES, ECR_PER_PAGE, EcrConnector } from './ecr.connector';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';

const ACCOUNT = '123456789012';
const REGION = 'us-east-1';
const DIGEST_A = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

/**
 * The discovery loop against the real database: integration → ECR (stubbed
 * DescribeRepositories / DescribeImages) → asset upserts → stale archival
 * on the next sync. Runs as ctem_app, so RLS applies exactly as in
 * deployment. HTTP is mocked — no live AWS.
 */
describe('ECR discovery (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let assets: AssetsService;
  let scheduler: DiscoverySchedulerService;
  let orgId: string;
  let orgBId: string;
  const events: Array<{ subject: string }> = [];
  let repositoryNames: string[] = [];
  let imagesByRepo: Record<string, Array<{ digest: string; tags: string[] }>> = {};
  let repoNext: string | undefined;
  let fetchStatus = 200;

  function callerXml(): string {
    return `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>${ACCOUNT}</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`;
  }

  function ecrTarget(init?: RequestInit): string {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    return headers['x-amz-target'] ?? headers['X-Amz-Target'] ?? '';
  }

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    orgId = (await createOrg(owner)).id;
    orgBId = (await createOrg(owner)).id;

    await owner.integration.create({
      data: {
        orgId,
        provider: 'ecr',
        displayName: 'discovery-int-test',
        config: { region: REGION },
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
    registry.register(new EcrConnector());
    assets = new AssetsService(prisma, bus);
    scheduler = new DiscoverySchedulerService(prisma, registry, assets);

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        if (fetchStatus !== 200) return new Response('boom', { status: fetchStatus });
        const href = String(url);
        const parsed = new URL(href);
        expect(parsed.hostname.endsWith('amazonaws.com')).toBe(true);
        expect(parsed.hostname).not.toContain('dkr.ecr');
        const body = String(init?.body ?? '');
        if (href.includes('sts.') && body.includes('GetCallerIdentity')) {
          return new Response(callerXml(), { status: 200 });
        }
        const target = ecrTarget(init);
        if (target.endsWith('.DescribeRepositories')) {
          expect(parsed.hostname).toBe(`api.ecr.${REGION}.amazonaws.com`);
          return new Response(
            JSON.stringify({
              repositories: repositoryNames.map((name) => ({
                repositoryName: name,
                registryId: ACCOUNT,
                repositoryArn: `arn:aws:ecr:${REGION}:${ACCOUNT}:repository/${name}`,
              })),
              ...(repoNext ? { nextToken: repoNext } : {}),
            }),
            { status: 200 },
          );
        }
        if (target.endsWith('.DescribeImages')) {
          expect(parsed.hostname).toBe(`api.ecr.${REGION}.amazonaws.com`);
          const payload = JSON.parse(body) as { repositoryName?: string };
          const name = payload.repositoryName ?? '';
          const images = imagesByRepo[name] ?? [];
          return new Response(
            JSON.stringify({
              imageDetails: images.map((img) => ({
                imageDigest: img.digest,
                imageTags: img.tags,
                registryId: ACCOUNT,
                repositoryName: name,
              })),
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
    delete process.env.AWS_ACCESS_KEY_ID;
    delete process.env.AWS_SECRET_ACCESS_KEY;
    await owner.organization.deleteMany({ where: { id: { in: [orgId, orgBId] } } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('inventories ECR images as container_image assets keyed by digest', async () => {
    repositoryNames = ['payments-api', 'worker'];
    imagesByRepo = {
      'payments-api': [{ digest: DIGEST_A, tags: ['latest', 'v1'] }],
      worker: [{ digest: DIGEST_B, tags: ['stable'] }],
    };
    repoNext = undefined;
    fetchStatus = 200;
    const results = await scheduler.syncOrg(orgId);
    expect(results).toEqual([
      expect.objectContaining({ provider: 'ecr', upserted: 2, archived: 0, error: null }),
    ]);

    const rows = await owner.asset.findMany({ where: { orgId }, orderBy: { name: 'asc' } });
    expect(rows.map((a) => a.externalKey)).toEqual([
      `ecr:${ACCOUNT}/payments-api@${DIGEST_A}`,
      `ecr:${ACCOUNT}/worker@${DIGEST_B}`,
    ]);
    expect(rows.every((a) => a.kind === 'container_image')).toBe(true);
    expect(rows.every((a) => a.source === 'ecr')).toBe(true);
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
    repoNext = undefined;
    fetchStatus = 200;
    const [result] = await scheduler.syncOrg(orgId);
    expect(result).toMatchObject({ upserted: 1, archived: 1 });

    const worker = await owner.asset.findUnique({
      where: {
        orgId_externalKey: {
          orgId,
          externalKey: `ecr:${ACCOUNT}/worker@${DIGEST_B}`,
        },
      },
    });
    expect(worker?.archivedAt).not.toBeNull();
  });

  it('GET-by-id on an org miss is 404, never 500 or empty-200', async () => {
    const owned = await owner.asset.findFirst({
      where: { orgId, source: 'ecr', archivedAt: null },
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
        provider: 'ecr',
        displayName: 'org-b-ecr',
        config: { region: REGION },
        credentialRef: 'env:AWS_ACCESS_KEY_ID',
      },
    });
    await owner.asset.create({
      data: {
        orgId: orgBId,
        kind: 'container_image',
        externalKey: `ecr:${ACCOUNT}/secret@${DIGEST_A}`,
        name: 'secret',
        source: 'ecr',
        integrationId: other.id,
      },
    });

    repositoryNames = ['payments-api'];
    imagesByRepo = {
      'payments-api': [{ digest: DIGEST_A, tags: ['latest'] }],
    };
    repoNext = undefined;
    fetchStatus = 200;
    await scheduler.syncOrg(orgId);

    const fromB = await prisma.withOrg(orgBId, (tx) => tx.asset.findMany());
    expect(fromB.map((a) => a.externalKey)).toEqual([`ecr:${ACCOUNT}/secret@${DIGEST_A}`]);
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
        externalKey: `ecr:${ACCOUNT}/keep@${DIGEST_B}`,
        name: 'keep',
        source: 'ecr',
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
        expect(parsed.hostname).not.toContain('dkr.ecr');
        const body = String(init?.body ?? '');
        if (href.includes('sts.') && body.includes('GetCallerIdentity')) {
          return new Response(callerXml(), { status: 200 });
        }
        const headers = (init?.headers ?? {}) as Record<string, string>;
        const target = headers['x-amz-target'] ?? headers['X-Amz-Target'] ?? '';
        if (target.endsWith('.DescribeImages')) {
          return new Response(JSON.stringify({ imageDetails: [] }), { status: 200 });
        }
        if (target.endsWith('.DescribeRepositories')) {
          page += 1;
          const names = Array.from({ length: ECR_PER_PAGE }, (_, i) => `img-t-${page}-${i}`);
          const next = page <= ECR_MAX_PAGES ? `more-${page}` : undefined;
          return new Response(
            JSON.stringify({
              repositories: names.map((name) => ({
                repositoryName: name,
                registryId: ACCOUNT,
              })),
              ...(next ? { nextToken: next } : {}),
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

  it('does not archive inventory when AWS_* credentials are missing', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const before = await owner.asset.findMany({
      where: { orgId, source: 'ecr', integrationId: first!.id, archivedAt: null },
    });
    expect(before.length).toBeGreaterThan(0);

    const token = process.env.AWS_ACCESS_KEY_ID;
    delete process.env.AWS_ACCESS_KEY_ID;

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/cannot be used|fails closed|env:AWS_\*/);
    expect(result.archived).toBe(0);

    const after = await owner.asset.findMany({
      where: { orgId, source: 'ecr', integrationId: first!.id, archivedAt: null },
    });
    expect(after.length).toBe(before.length);

    process.env.AWS_ACCESS_KEY_ID = token;
  });

  it('refuses a tenant-writable endpoint without wiping inventory or sending keys', async () => {
    const first = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    const bad = await owner.integration.create({
      data: {
        orgId,
        provider: 'ecr',
        displayName: 'exfil-endpoint',
        config: {
          region: REGION,
          registryUrl: 'https://123.dkr.ecr.us-east-1.amazonaws.com',
          endpoint: 'https://evil.example',
        },
        credentialRef: 'env:AWS_ACCESS_KEY_ID',
      },
    });

    const result = await scheduler.syncIntegration(bad);
    expect(result.error).toMatch(/tenant-writable ECR endpoint/);
    expect(result.archived).toBe(0);
    expect(result.error).not.toMatch(/evil\.example/);

    const row = await owner.integration.findUnique({ where: { id: bad.id } });
    expect(row?.lastSyncError).toMatch(/tenant-writable ECR endpoint/);

    const kept = await owner.asset.findMany({
      where: { orgId, source: 'ecr', integrationId: first!.id, archivedAt: null },
    });
    expect(kept.length).toBeGreaterThan(0);
  });
});

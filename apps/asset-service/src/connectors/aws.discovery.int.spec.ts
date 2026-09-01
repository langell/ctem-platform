import { NotFoundException } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { AWS_MAX_PAGES, AWS_PER_PAGE, AwsConnector } from './aws.connector';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';

const ACCOUNT = '123456789012';
const REGION = 'us-east-1';

/**
 * The discovery loop against the real database: integration → AWS (stubbed)
 * → asset upserts → stale archival on the next sync. Runs as ctem_app, so RLS
 * applies exactly as in deployment. HTTP is mocked — no live AWS.
 */
describe('AWS discovery (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let assets: AssetsService;
  let scheduler: DiscoverySchedulerService;
  let orgId: string;
  let orgBId: string;
  const events: Array<{ subject: string }> = [];
  let instanceIds: string[] = [];
  let nextToken: string | undefined;
  let fetchStatus = 200;

  function callerXml(): string {
    return `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>${ACCOUNT}</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`;
  }

  function instancesXml(): string {
    const reservations = instanceIds
      .map(
        (id) =>
          `<item><instancesSet><item><instanceId>${id}</instanceId><instanceState><name>running</name></instanceState><privateIpAddress>10.0.0.8</privateIpAddress></item></instancesSet></item>`,
      )
      .join('');
    return `<DescribeInstancesResponse><reservationSet>${reservations}</reservationSet>${
      nextToken ? `<nextToken>${nextToken}</nextToken>` : ''
    }</DescribeInstancesResponse>`;
  }

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    orgId = (await createOrg(owner)).id;
    orgBId = (await createOrg(owner)).id;

    await owner.integration.create({
      data: {
        orgId,
        provider: 'aws',
        displayName: 'discovery-int-test',
        config: { region: REGION, resourceTypes: ['ec2_instance'] },
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
    registry.register(new AwsConnector());
    assets = new AssetsService(prisma, bus);
    scheduler = new DiscoverySchedulerService(prisma, registry, assets);

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        if (fetchStatus !== 200) return new Response('boom', { status: fetchStatus });
        const href = String(url);
        const body = String(init?.body ?? '');
        if (href.includes('sts.') && body.includes('GetCallerIdentity')) {
          return new Response(callerXml(), { status: 200 });
        }
        if (href.includes('ec2.') && body.includes('DescribeInstances')) {
          return new Response(instancesXml(), { status: 200 });
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

  it('inventories AWS resources as cloud_resource and publishes discovery events', async () => {
    instanceIds = ['i-alpha', 'i-beta'];
    nextToken = undefined;
    fetchStatus = 200;
    const results = await scheduler.syncOrg(orgId);
    expect(results).toEqual([
      expect.objectContaining({ provider: 'aws', upserted: 2, archived: 0, error: null }),
    ]);

    const rows = await owner.asset.findMany({ where: { orgId }, orderBy: { name: 'asc' } });
    expect(rows.map((a) => a.externalKey)).toEqual([
      `aws:${ACCOUNT}:ec2:${REGION}:i-alpha`,
      `aws:${ACCOUNT}:ec2:${REGION}:i-beta`,
    ]);
    expect(rows.every((a) => a.kind === 'cloud_resource')).toBe(true);
    expect(rows.every((a) => a.source === 'aws')).toBe(true);
    expect(events.filter((e) => e.subject === 'ctem.asset.discovered')).toHaveLength(2);

    const integration = await owner.integration.findFirst({
      where: { orgId, displayName: 'discovery-int-test' },
    });
    expect(rows.every((a) => a.integrationId === integration?.id)).toBe(true);
    expect(integration?.lastSyncAt).not.toBeNull();
    expect(integration?.lastSyncError).toBeNull();
  });

  it('archives assets that stop appearing instead of deleting them', async () => {
    instanceIds = ['i-alpha'];
    nextToken = undefined;
    fetchStatus = 200;
    const [result] = await scheduler.syncOrg(orgId);
    expect(result).toMatchObject({ upserted: 1, archived: 1 });

    const beta = await owner.asset.findUnique({
      where: {
        orgId_externalKey: { orgId, externalKey: `aws:${ACCOUNT}:ec2:${REGION}:i-beta` },
      },
    });
    expect(beta?.archivedAt).not.toBeNull();
  });

  it('GET-by-id on an org miss is 404, never 500 or empty-200', async () => {
    const owned = await owner.asset.findFirst({
      where: { orgId, source: 'aws', archivedAt: null },
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
        provider: 'aws',
        displayName: 'org-b-aws',
        config: { region: REGION, resourceTypes: ['ec2_instance'] },
        credentialRef: 'env:AWS_ACCESS_KEY_ID',
      },
    });
    await owner.asset.create({
      data: {
        orgId: orgBId,
        kind: 'cloud_resource',
        externalKey: `aws:${ACCOUNT}:ec2:${REGION}:i-secret`,
        name: 'secret',
        source: 'aws',
        integrationId: other.id,
      },
    });

    instanceIds = ['i-alpha'];
    nextToken = undefined;
    fetchStatus = 200;
    await scheduler.syncOrg(orgId);

    const fromB = await prisma.withOrg(orgBId, (tx) => tx.asset.findMany());
    expect(fromB.map((a) => a.externalKey)).toEqual([`aws:${ACCOUNT}:ec2:${REGION}:i-secret`]);
    expect(fromB.some((a) => a.externalKey.endsWith(':i-alpha'))).toBe(false);

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
        externalKey: `aws:${ACCOUNT}:ec2:${REGION}:i-keep`,
        name: 'keep',
        source: 'aws',
        integrationId: first!.id,
      },
    });

    let page = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        const href = String(url);
        const body = String(init?.body ?? '');
        if (href.includes('sts.') && body.includes('GetCallerIdentity')) {
          return new Response(callerXml(), { status: 200 });
        }
        if (href.includes('ec2.') && body.includes('DescribeInstances')) {
          page += 1;
          const ids = Array.from({ length: AWS_PER_PAGE }, (_, i) => `i-t-${page}-${i}`);
          const token = page <= AWS_MAX_PAGES ? `more-${page}` : undefined;
          const reservations = ids
            .map(
              (id) =>
                `<item><instancesSet><item><instanceId>${id}</instanceId><instanceState><name>running</name></instanceState></item></instancesSet></item>`,
            )
            .join('');
          return new Response(
            `<DescribeInstancesResponse><reservationSet>${reservations}</reservationSet><nextToken>${token}</nextToken></DescribeInstancesResponse>`,
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
      where: { orgId, source: 'aws', integrationId: first!.id, archivedAt: null },
    });
    expect(before.length).toBeGreaterThan(0);

    const token = process.env.AWS_ACCESS_KEY_ID;
    delete process.env.AWS_ACCESS_KEY_ID;

    const result = await scheduler.syncIntegration(first!);
    expect(result.error).toMatch(/cannot be used|fails closed/);
    expect(result.archived).toBe(0);

    const after = await owner.asset.findMany({
      where: { orgId, source: 'aws', integrationId: first!.id, archivedAt: null },
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
        provider: 'aws',
        displayName: 'exfil-endpoint',
        config: { region: REGION, endpoint: 'https://evil.example' },
        credentialRef: 'env:AWS_ACCESS_KEY_ID',
      },
    });

    const result = await scheduler.syncIntegration(bad);
    expect(result.error).toMatch(/tenant-writable AWS endpoint/);
    expect(result.archived).toBe(0);
    expect(result.error).not.toMatch(/evil\.example/);

    const row = await owner.integration.findUnique({ where: { id: bad.id } });
    expect(row?.lastSyncError).toMatch(/tenant-writable AWS endpoint/);

    const kept = await owner.asset.findMany({
      where: { orgId, source: 'aws', integrationId: first!.id, archivedAt: null },
    });
    expect(kept.length).toBeGreaterThan(0);
  });
});

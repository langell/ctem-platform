import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import type { EventBus } from '@ctem/events';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, ownerClient } from '@ctem/testing';
import { AssetsService } from '../assets/assets.service';
import { ConnectorRegistry } from '../connectors/connector.registry';
import { DiscoverySchedulerService } from '../connectors/discovery-scheduler.service';
import { GitHubConnector, type GitHubRepo } from '../connectors/github.connector';
import { resetInventoryEgressPolicy } from '../connectors/inventory-egress';
import { decryptIntegrationSecret } from '../secrets/credential-crypto';
import { IntegrationsService } from './integrations.service';

const TOKEN = 'ghs_e2e_stub_token_do_not_leak';

describe('GitHub connect tenancy', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let scheduler: DiscoverySchedulerService;
  let service: IntegrationsService;
  let orgA: string;
  let orgB: string;
  let mode: 'ok' | 'invalid' | 'missing-owner' | 'boom' = 'ok';

  const repo = (name: string): GitHubRepo => ({
    name,
    full_name: `acme/${name}`,
    private: true,
    archived: false,
    fork: false,
    html_url: `https://github.com/acme/${name}`,
    default_branch: 'main',
    owner: { login: 'acme' },
  });

  beforeAll(async () => {
    resetInventoryEgressPolicy();
    owner = ownerClient();
    prisma = new PrismaService();
    orgA = (await createOrg(owner)).id;
    orgB = (await createOrg(owner)).id;

    const bus = { publish: vi.fn(async () => undefined) } as unknown as EventBus;
    const registry = new ConnectorRegistry();
    registry.register(new GitHubConnector());
    scheduler = new DiscoverySchedulerService(prisma, registry, new AssetsService(prisma, bus));
    service = new IntegrationsService(prisma, scheduler);

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        const path = new URL(String(url)).pathname;
        if (mode === 'invalid' && path === '/user') {
          return new Response(TOKEN, { status: 401 });
        }
        if (mode === 'boom' && path.endsWith('/repos')) {
          return new Response(TOKEN, { status: 500 });
        }
        if (path === '/user')
          return new Response(JSON.stringify({ login: 'acme' }), { status: 200 });
        if (path === '/orgs/acme')
          return new Response(JSON.stringify({ login: 'acme' }), { status: 200 });
        if (path === '/orgs/missing')
          return new Response(JSON.stringify({ message: 'Not Found' }), { status: 404 });
        if (path.endsWith('/repos')) {
          return new Response(JSON.stringify([repo('payments-api'), repo('web')]), { status: 200 });
        }
        return new Response(JSON.stringify({ message: 'no' }), { status: 404 });
      }),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    await owner.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('rejects an invalid token before saving and does not echo it', async () => {
    mode = 'invalid';
    await expect(
      service.connectGitHub(orgA, { owner: 'acme', ownerType: 'org', token: TOKEN }),
    ).rejects.toBeInstanceOf(BadRequestException);
    try {
      await service.connectGitHub(orgA, { owner: 'acme', ownerType: 'org', token: TOKEN });
    } catch (err) {
      expect(err).toBeInstanceOf(BadRequestException);
      const body = JSON.stringify((err as BadRequestException).getResponse());
      expect(body).toContain('Invalid GitHub token');
      expect(body).not.toContain(TOKEN);
    }
    expect(await owner.integration.count({ where: { orgId: orgA } })).toBe(0);
    mode = 'ok';
  });

  it('stores the token encrypted, discovers that integration, and omits the token from the view', async () => {
    const view = await service.connectGitHub(orgA, {
      owner: 'acme',
      ownerType: 'org',
      token: TOKEN,
    });
    const blob = JSON.stringify(view);
    expect(blob).not.toContain(TOKEN);
    expect(view).not.toHaveProperty('credentialRef');
    expect(view).not.toHaveProperty('token');
    expect(view.hasCredential).toBe(true);
    expect(view.lastSyncError).toBeNull();
    expect(view.displayName).toBe('github:acme');
    expect(view.owner).toBe('acme');

    const row = await owner.integration.findUnique({ where: { id: view.id } });
    expect(row?.credentialRef).toBe(`secret:${view.id}`);
    expect(JSON.stringify(row?.config)).not.toContain(TOKEN);
    expect(row?.lastSyncError).toBeNull();

    const secret = await owner.integrationSecret.findUnique({ where: { integrationId: view.id } });
    expect(secret).toBeTruthy();
    expect(Buffer.from(secret!.ciphertext).includes(Buffer.from(TOKEN))).toBe(false);
    expect(
      decryptIntegrationSecret(
        {
          ciphertext: Buffer.from(secret!.ciphertext),
          iv: Buffer.from(secret!.iv),
          authTag: Buffer.from(secret!.authTag),
          keyId: secret!.keyId,
        },
        orgA,
        view.id,
      ),
    ).toBe(TOKEN);

    const assets = await owner.asset.findMany({ where: { orgId: orgA }, orderBy: { name: 'asc' } });
    expect(assets.map((asset) => asset.externalKey)).toEqual([
      'github:acme/payments-api',
      'github:acme/web',
    ]);
    expect(assets.every((asset) => asset.integrationId === view.id)).toBe(true);
  });

  it('returns 409 for a duplicate display name and does not include the token', async () => {
    await expect(
      service.connectGitHub(orgA, { owner: 'acme', ownerType: 'org', token: TOKEN }),
    ).rejects.toBeInstanceOf(ConflictException);
    try {
      await service.connectGitHub(orgA, { owner: 'acme', ownerType: 'org', token: TOKEN });
    } catch (err) {
      expect(JSON.stringify((err as ConflictException).getResponse())).not.toContain(TOKEN);
    }
  });

  it('refuses org B list, delete, decrypt, discover, and asset reads', async () => {
    const [listedA] = await service.list(orgA);
    expect(listedA).toBeTruthy();
    const listedB = await service.list(orgB);
    expect(listedB).toEqual([]);
    expect(JSON.stringify(listedA)).not.toContain(TOKEN);

    await expect(service.remove(orgB, listedA.id)).rejects.toBeInstanceOf(NotFoundException);

    const secret = await owner.integrationSecret.findUnique({
      where: { integrationId: listedA.id },
    });
    expect(() =>
      decryptIntegrationSecret(
        {
          ciphertext: Buffer.from(secret!.ciphertext),
          iv: Buffer.from(secret!.iv),
          authTag: Buffer.from(secret!.authTag),
          keyId: secret!.keyId,
        },
        orgB,
        listedA.id,
      ),
    ).toThrow(/could not be decrypted/);

    const hidden = await prisma.withOrg(orgB, (tx) => tx.integrationSecret.findMany());
    expect(hidden).toEqual([]);

    const before = await owner.integration.findUnique({ where: { id: listedA.id } });
    const discovered = await scheduler.syncOrg(orgB);
    expect(discovered).toEqual([]);
    const after = await owner.integration.findUnique({ where: { id: listedA.id } });
    expect(after?.lastSyncAt?.toISOString()).toBe(before?.lastSyncAt?.toISOString());

    const assetsB = await prisma.withOrg(orgB, (tx) => tx.asset.findMany());
    expect(assetsB).toEqual([]);
    const assetsA = await prisma.withOrg(orgA, (tx) => tx.asset.findMany());
    expect(assetsA.map((asset) => asset.externalKey).sort()).toEqual([
      'github:acme/payments-api',
      'github:acme/web',
    ]);
  });

  it('records a sync error without the token or archiveStale when GitHub returns the token in the body', async () => {
    mode = 'boom';
    const [row] = await service.list(orgA);
    const integration = await owner.integration.findUnique({ where: { id: row.id } });
    const result = await scheduler.syncIntegration(integration!);
    expect(result.archived).toBe(0);
    expect(result.error).toMatch(/500/);
    expect(result.error).not.toContain(TOKEN);
    const stored = await owner.integration.findUnique({ where: { id: row.id } });
    expect(stored?.lastSyncError).toMatch(/500/);
    expect(stored?.lastSyncError).not.toContain(TOKEN);
    const assets = await owner.asset.findMany({ where: { orgId: orgA } });
    expect(assets.every((asset) => asset.archivedAt === null)).toBe(true);
    mode = 'ok';
  });

  it('does not archive when the secret row cannot be decrypted', async () => {
    const [row] = await service.list(orgA);
    await owner.integrationSecret.update({
      where: { integrationId: row.id },
      data: { ciphertext: Buffer.from('not-the-ciphertext') },
    });
    const integration = await owner.integration.findUnique({ where: { id: row.id } });
    const result = await scheduler.syncIntegration(integration!);
    expect(result.archived).toBe(0);
    expect(result.upserted).toBe(0);
    expect(result.error).toBe('GitHub credential could not be decrypted');
    expect(result.error).not.toContain(TOKEN);
    const assets = await owner.asset.findMany({ where: { orgId: orgA } });
    expect(assets.every((asset) => asset.archivedAt === null)).toBe(true);
  });

  it('returns 400 when the GitHub owner does not exist and saves nothing new', async () => {
    const before = await owner.integration.count({ where: { orgId: orgA } });
    await expect(
      service.connectGitHub(orgA, { owner: 'missing', ownerType: 'org', token: TOKEN }),
    ).rejects.toBeInstanceOf(BadRequestException);
    try {
      await service.connectGitHub(orgA, { owner: 'missing', ownerType: 'org', token: TOKEN });
    } catch (err) {
      const body = JSON.stringify((err as BadRequestException).getResponse());
      expect(body).toContain('GitHub owner not found');
      expect(body).not.toContain(TOKEN);
    }
    expect(await owner.integration.count({ where: { orgId: orgA } })).toBe(before);
  });
});

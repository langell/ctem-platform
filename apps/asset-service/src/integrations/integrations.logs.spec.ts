import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { CREDENTIAL_KEY_BYTES, resetEnvCache } from '@ctem/config';
import type { PrismaService } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import type { AssetsService } from '../assets/assets.service';
import { ConnectorRegistry } from '../connectors/connector.registry';
import { DiscoverySchedulerService } from '../connectors/discovery-scheduler.service';
import { GitHubConnector } from '../connectors/github.connector';
import { resetInventoryEgressPolicy } from '../connectors/inventory-egress';
import { IntegrationsService } from './integrations.service';

const TOKEN = 'ghp_LogSpyDistinctiveToken9f3c';
const ORG = '11111111-1111-4111-8111-111111111111';
const OTHER_ORG = '22222222-2222-4222-8222-222222222222';
const KEY = Buffer.alloc(CREDENTIAL_KEY_BYTES, 9).toString('base64');

interface Row {
  id: string;
  orgId: string;
  provider: string;
  displayName: string;
  config: unknown;
  credentialRef: string | null;
  enabled: boolean;
  lastSyncAt: Date | null;
  lastSyncError: string | null;
  createdAt: Date;
}

interface SecretRow {
  integrationId: string;
  orgId: string;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  authTag: Uint8Array;
  keyId: string;
}

function matches(
  row: { id: string; orgId: string; provider: string; credentialRef: string | null },
  where: Record<string, unknown> | undefined,
): boolean {
  if (!where) return true;
  if (typeof where.id === 'string' && row.id !== where.id) return false;
  if (typeof where.orgId === 'string' && row.orgId !== where.orgId) return false;
  if (typeof where.provider === 'string' && row.provider !== where.provider) return false;
  const ref = where.credentialRef as { startsWith?: string } | undefined;
  if (ref?.startsWith && !(row.credentialRef ?? '').startsWith(ref.startsWith)) return false;
  return true;
}

function memoryPrisma() {
  const integrations = new Map<string, Row>();
  const secrets = new Map<string, SecretRow>();
  let withOrgCalls = 0;
  const tx = {
    integration: {
      create: async ({
        data,
      }: {
        data: Omit<Row, 'createdAt' | 'lastSyncAt' | 'lastSyncError'> & Partial<Row>;
      }) => {
        const row: Row = {
          lastSyncAt: null,
          lastSyncError: null,
          createdAt: new Date(),
          ...data,
        };
        integrations.set(row.id, row);
        return row;
      },
      findUnique: async ({
        where,
        include,
      }: {
        where: { id: string };
        include?: { secret?: boolean };
      }) => {
        const row = integrations.get(where.id);
        if (!row) return null;
        if (include?.secret) return { ...row, secret: secrets.get(row.id) ?? null };
        return row;
      },
      findMany: async ({
        where,
        include,
      }: {
        where?: Record<string, unknown>;
        include?: { secret?: boolean };
      }) =>
        [...integrations.values()]
          .filter((row) => matches(row, where))
          .map((row) => (include?.secret ? { ...row, secret: secrets.get(row.id) ?? null } : row)),
      update: async ({ where, data }: { where: { id: string }; data: Partial<Row> }) => {
        const row = integrations.get(where.id);
        if (!row) throw new Error('missing integration');
        Object.assign(row, data);
        return row;
      },
      deleteMany: async ({ where }: { where: Record<string, unknown> }) => {
        let count = 0;
        for (const [id, row] of integrations) {
          if (!matches(row, where)) continue;
          integrations.delete(id);
          count += 1;
        }
        return { count };
      },
    },
    integrationSecret: {
      create: async ({ data }: { data: SecretRow }) => {
        secrets.set(data.integrationId, data);
        return data;
      },
      findUnique: async ({ where }: { where: { integrationId: string } }) =>
        secrets.get(where.integrationId) ?? null,
      deleteMany: async ({ where }: { where: { integrationId?: string; orgId?: string } }) => {
        let count = 0;
        for (const [id, row] of secrets) {
          if (where.integrationId && id !== where.integrationId) continue;
          if (where.orgId && row.orgId !== where.orgId) continue;
          secrets.delete(id);
          count += 1;
        }
        return { count };
      },
    },
  };
  return {
    integrations,
    secrets,
    calls: () => withOrgCalls,
    resetCalls: () => {
      withOrgCalls = 0;
    },
    client: {
      withOrg: async (_orgId: string, fn: (inner: typeof tx) => Promise<unknown>) => {
        withOrgCalls += 1;
        return fn(tx);
      },
    } as unknown as PrismaService,
  };
}

function pinoStream(logger: object): { write: (chunk: string) => boolean } {
  let current: object | null = logger;
  while (current) {
    for (const sym of Object.getOwnPropertySymbols(current)) {
      if (sym.description === 'pino.stream') {
        return (current as Record<symbol, { write: (chunk: string) => boolean }>)[sym];
      }
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw new Error('pino stream not found');
}

function captureLogs(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const stream = pinoStream(rootLogger);
  const orig = stream.write.bind(stream);
  stream.write = (chunk: string) => {
    lines.push(String(chunk));
    return orig(chunk);
  };
  return {
    lines,
    restore: () => {
      stream.write = orig;
    },
  };
}

describe('GitHub connect logs and delete', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.CREDENTIAL_ENCRYPTION_KEY;
    resetEnvCache();
  });

  it('never logs the token on a rejected connect, a successful connect, or discovery', async () => {
    process.env.CREDENTIAL_ENCRYPTION_KEY = KEY;
    process.env.GITHUB_API_URL = 'https://api.github.com';
    process.env.NODE_ENV = 'test';
    resetEnvCache();
    resetInventoryEgressPolicy();

    const db = memoryPrisma();
    const captured = captureLogs();
    const registry = new ConnectorRegistry();
    registry.register(new GitHubConnector());
    const assets = {
      upsert: vi.fn(async () => ({})),
      archiveStale: vi.fn(async () => ({ count: 0 })),
    } as unknown as AssetsService;
    const scheduler = new DiscoverySchedulerService(db.client, registry, assets);
    const service = new IntegrationsService(db.client, scheduler);

    let mode: 'invalid' | 'ok' | 'boom' = 'invalid';
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        const path = new URL(String(url)).pathname;
        if (mode === 'invalid' && path === '/user') {
          return new Response('Bad credentials', { status: 401 });
        }
        if (mode === 'boom' && path.endsWith('/repos')) {
          return new Response(TOKEN, { status: 500 });
        }
        if (path === '/user' || path === '/orgs/acme') {
          return new Response(JSON.stringify({ login: 'acme' }), { status: 200 });
        }
        if (path.endsWith('/repos')) {
          return new Response(
            JSON.stringify([
              {
                name: 'payments-api',
                full_name: 'acme/payments-api',
                private: true,
                archived: false,
                fork: false,
                html_url: 'https://github.com/acme/payments-api',
                default_branch: 'main',
                owner: { login: 'acme' },
              },
            ]),
            { status: 200 },
          );
        }
        return new Response('no', { status: 404 });
      }),
    );

    try {
      await expect(
        service.connectGitHub(ORG, { owner: 'acme', ownerType: 'org', token: TOKEN }),
      ).rejects.toBeInstanceOf(BadRequestException);

      mode = 'ok';
      const view = await service.connectGitHub(ORG, {
        owner: 'acme',
        ownerType: 'org',
        token: TOKEN,
      });
      expect(view.lastSyncError).toBeNull();

      mode = 'boom';
      const row = db.integrations.get(view.id);
      const sync = await scheduler.syncIntegration(row!);
      expect(sync.error).toBeTruthy();
      expect(sync.error).not.toContain(TOKEN);

      const blob = captured.lines.join('\n');
      expect(blob).toContain('github token validation rejected');
      expect(blob).toContain('github integration connected');
      expect(blob).toContain('github discovery complete');
      expect(blob).toContain('discovery sync failed');
      expect(blob).not.toContain(TOKEN);
    } finally {
      captured.restore();
    }
  });

  it('deletes the pasted GitHub integration and its secret in one transaction', async () => {
    const db = memoryPrisma();
    const scheduler = { syncIntegration: vi.fn() } as unknown as DiscoverySchedulerService;
    const service = new IntegrationsService(db.client, scheduler);
    const id = randomUUID();
    const platformId = randomUUID();
    db.integrations.set(id, {
      id,
      orgId: ORG,
      provider: 'github',
      displayName: 'github:acme',
      config: { owner: 'acme', ownerType: 'org' },
      credentialRef: `secret:${id}`,
      enabled: true,
      lastSyncAt: null,
      lastSyncError: null,
      createdAt: new Date(),
    });
    db.secrets.set(id, {
      integrationId: id,
      orgId: ORG,
      ciphertext: new Uint8Array([1]),
      iv: new Uint8Array(12),
      authTag: new Uint8Array(16),
      keyId: 'v1',
    });
    db.integrations.set(platformId, {
      id: platformId,
      orgId: ORG,
      provider: 'github',
      displayName: 'platform',
      config: {},
      credentialRef: 'env:GITHUB_TOKEN',
      enabled: true,
      lastSyncAt: null,
      lastSyncError: null,
      createdAt: new Date(),
    });

    const listed = await service.list(ORG);
    expect(listed.map((row) => row.id)).toEqual([id]);

    db.resetCalls();
    await service.remove(ORG, id);
    expect(db.calls()).toBe(1);
    expect(db.integrations.has(id)).toBe(false);
    expect(db.secrets.has(id)).toBe(false);
    expect(db.integrations.has(platformId)).toBe(true);

    await expect(service.remove(OTHER_ORG, platformId)).rejects.toBeInstanceOf(NotFoundException);
    expect(db.integrations.has(platformId)).toBe(true);
    await expect(service.remove(ORG, platformId)).rejects.toBeInstanceOf(NotFoundException);
    expect(db.integrations.has(platformId)).toBe(true);
  });
});

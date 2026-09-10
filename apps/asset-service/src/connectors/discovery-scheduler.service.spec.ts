import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DISCOVERY_SCHEDULE_LEASE_KEY,
  MemoryLeaseStore,
  UnavailableLeaseStore,
} from '@ctem/coordination';
import type { PrismaService } from '@ctem/db';
import type { AssetsService } from '../assets/assets.service';
import { ConnectorRegistry } from './connector.registry';
import {
  DISCOVERY_SCHEDULE_TICK_MS,
  DiscoverySchedulerService,
} from './discovery-scheduler.service';

function prismaMock(integrations: unknown[] = []) {
  return {
    unsafeCrossTenant: vi.fn(async () => integrations),
    withOrg: vi.fn(async (_orgId: string, fn: (tx: { integration: { findMany: () => Promise<unknown[]> } }) => unknown) =>
      fn({ integration: { findMany: async () => integrations } }),
    ),
  };
}

describe('DiscoverySchedulerService leader lease', () => {
  const services: DiscoverySchedulerService[] = [];

  afterEach(async () => {
    await Promise.all(services.splice(0).map((svc) => svc.onModuleDestroy()));
  });

  it('keeps the fifteen-minute cadence', () => {
    const spy = vi.spyOn(global, 'setInterval');
    const svc = new DiscoverySchedulerService(
      prismaMock() as unknown as PrismaService,
      new ConnectorRegistry(),
      {} as AssetsService,
      new MemoryLeaseStore(),
    );
    services.push(svc);
    svc.onApplicationBootstrap();
    expect(DISCOVERY_SCHEDULE_TICK_MS).toBe(15 * 60_000);
    expect(spy.mock.calls.some((call) => call[1] === DISCOVERY_SCHEDULE_TICK_MS)).toBe(true);
    spy.mockRestore();
  });

  it('lets a single replica acquire the lease and tick', async () => {
    const prisma = prismaMock();
    const svc = new DiscoverySchedulerService(
      prisma as unknown as PrismaService,
      new ConnectorRegistry(),
      {} as AssetsService,
      new MemoryLeaseStore(),
    );
    services.push(svc);
    await svc.runScheduledTick();
    expect(prisma.unsafeCrossTenant).toHaveBeenCalledTimes(1);
  });

  it('lets only one of two competitors sync from the interval', async () => {
    const store = new MemoryLeaseStore();
    const prismaA = prismaMock();
    const prismaB = prismaMock();
    const a = new DiscoverySchedulerService(
      prismaA as unknown as PrismaService,
      new ConnectorRegistry(),
      {} as AssetsService,
      store,
    );
    const b = new DiscoverySchedulerService(
      prismaB as unknown as PrismaService,
      new ConnectorRegistry(),
      {} as AssetsService,
      store,
    );
    services.push(a, b);

    await Promise.all([a.runScheduledTick(), b.runScheduledTick()]);
    expect(prismaA.unsafeCrossTenant.mock.calls.length + prismaB.unsafeCrossTenant.mock.calls.length).toBe(1);
  });

  it('fails over after TTL expiry so the follower becomes the ticker', async () => {
    const store = new MemoryLeaseStore();
    const prismaA = prismaMock();
    const prismaB = prismaMock();
    const a = new DiscoverySchedulerService(
      prismaA as unknown as PrismaService,
      new ConnectorRegistry(),
      {} as AssetsService,
      store,
    );
    const b = new DiscoverySchedulerService(
      prismaB as unknown as PrismaService,
      new ConnectorRegistry(),
      {} as AssetsService,
      store,
    );
    services.push(a, b);

    await a.runScheduledTick();
    expect(prismaA.unsafeCrossTenant).toHaveBeenCalledTimes(1);

    store.expire(DISCOVERY_SCHEDULE_LEASE_KEY);
    await b.runScheduledTick();
    expect(prismaB.unsafeCrossTenant).toHaveBeenCalledTimes(1);
  });

  it('does not tick on either replica when Redis is down', async () => {
    const store = new UnavailableLeaseStore();
    const prismaA = prismaMock();
    const prismaB = prismaMock();
    const a = new DiscoverySchedulerService(
      prismaA as unknown as PrismaService,
      new ConnectorRegistry(),
      {} as AssetsService,
      store,
    );
    const b = new DiscoverySchedulerService(
      prismaB as unknown as PrismaService,
      new ConnectorRegistry(),
      {} as AssetsService,
      store,
    );
    services.push(a, b);

    await a.runScheduledTick();
    await b.runScheduledTick();
    expect(prismaA.unsafeCrossTenant).not.toHaveBeenCalled();
    expect(prismaB.unsafeCrossTenant).not.toHaveBeenCalled();
  });

  it('does not gate manual syncOrg behind the lease', async () => {
    const prisma = prismaMock([{ id: 'int-1' }]);
    const registry = new ConnectorRegistry();
    const svc = new DiscoverySchedulerService(
      prisma as unknown as PrismaService,
      registry,
      {} as AssetsService,
      new UnavailableLeaseStore(),
    );
    services.push(svc);

    const results = await svc.syncOrg('org-1');
    expect(prisma.withOrg).toHaveBeenCalled();
    expect(prisma.unsafeCrossTenant).not.toHaveBeenCalled();
    expect(results).toEqual([
      expect.objectContaining({
        integrationId: 'int-1',
        error: 'no connector registered',
      }),
    ]);
  });
});

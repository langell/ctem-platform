import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  MemoryLeaseStore,
  SCAN_SCHEDULE_LEASE_KEY,
  UnavailableLeaseStore,
} from '@ctem/coordination';
import type { PrismaService } from '@ctem/db';
import { SCAN_SCHEDULE_TICK_MS, ScanScheduleService } from './scan-schedule.service';
import type { ScanDispatcherService } from './scan-dispatcher.service';

function prismaMock() {
  return {
    unsafeCrossTenant: vi.fn(async () => []),
    withOrg: vi.fn(),
  };
}

function dispatcherMock() {
  return { createScan: vi.fn(async () => ({ id: 'scan-1' })) };
}

describe('ScanScheduleService leader lease', () => {
  const services: ScanScheduleService[] = [];

  afterEach(async () => {
    await Promise.all(services.splice(0).map((svc) => svc.onModuleDestroy()));
  });

  it('keeps the five-minute cadence', () => {
    const spy = vi.spyOn(global, 'setInterval');
    const svc = new ScanScheduleService(
      prismaMock() as unknown as PrismaService,
      dispatcherMock() as unknown as ScanDispatcherService,
      new MemoryLeaseStore(),
    );
    services.push(svc);
    svc.onApplicationBootstrap();
    expect(SCAN_SCHEDULE_TICK_MS).toBe(5 * 60_000);
    expect(spy.mock.calls.some((call) => call[1] === SCAN_SCHEDULE_TICK_MS)).toBe(true);
    spy.mockRestore();
  });

  it('lets a single replica acquire the lease and tick', async () => {
    const prisma = prismaMock();
    const svc = new ScanScheduleService(
      prisma as unknown as PrismaService,
      dispatcherMock() as unknown as ScanDispatcherService,
      new MemoryLeaseStore(),
    );
    services.push(svc);
    await svc.runScheduledTick();
    expect(prisma.unsafeCrossTenant).toHaveBeenCalledTimes(1);
  });

  it('lets only one of two competitors dispatch a scheduled window', async () => {
    const store = new MemoryLeaseStore();
    const prismaA = prismaMock();
    const prismaB = prismaMock();
    const a = new ScanScheduleService(
      prismaA as unknown as PrismaService,
      dispatcherMock() as unknown as ScanDispatcherService,
      store,
    );
    const b = new ScanScheduleService(
      prismaB as unknown as PrismaService,
      dispatcherMock() as unknown as ScanDispatcherService,
      store,
    );
    services.push(a, b);

    await Promise.all([a.runScheduledTick(), b.runScheduledTick()]);

    const ticks = Number(prismaA.unsafeCrossTenant.mock.calls.length) + Number(prismaB.unsafeCrossTenant.mock.calls.length);
    expect(ticks).toBe(1);
    expect(prismaA.unsafeCrossTenant.mock.calls.length + prismaB.unsafeCrossTenant.mock.calls.length).toBe(1);
  });

  it('fails over after TTL expiry so the follower becomes the ticker', async () => {
    const store = new MemoryLeaseStore();
    const prismaA = prismaMock();
    const prismaB = prismaMock();
    const a = new ScanScheduleService(
      prismaA as unknown as PrismaService,
      dispatcherMock() as unknown as ScanDispatcherService,
      store,
    );
    const b = new ScanScheduleService(
      prismaB as unknown as PrismaService,
      dispatcherMock() as unknown as ScanDispatcherService,
      store,
    );
    services.push(a, b);

    await a.runScheduledTick();
    expect(prismaA.unsafeCrossTenant).toHaveBeenCalledTimes(1);
    expect(prismaB.unsafeCrossTenant).not.toHaveBeenCalled();

    store.expire(SCAN_SCHEDULE_LEASE_KEY);
    await b.runScheduledTick();
    expect(prismaB.unsafeCrossTenant).toHaveBeenCalledTimes(1);
  });

  it('does not tick on either replica when Redis is down', async () => {
    const store = new UnavailableLeaseStore();
    const prismaA = prismaMock();
    const prismaB = prismaMock();
    const a = new ScanScheduleService(
      prismaA as unknown as PrismaService,
      dispatcherMock() as unknown as ScanDispatcherService,
      store,
    );
    const b = new ScanScheduleService(
      prismaB as unknown as PrismaService,
      dispatcherMock() as unknown as ScanDispatcherService,
      store,
    );
    services.push(a, b);

    await a.runScheduledTick();
    await b.runScheduledTick();

    expect(prismaA.unsafeCrossTenant).not.toHaveBeenCalled();
    expect(prismaB.unsafeCrossTenant).not.toHaveBeenCalled();
  });
});

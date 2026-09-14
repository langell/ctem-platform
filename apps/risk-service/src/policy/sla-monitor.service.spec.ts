import { afterEach, describe, expect, it, vi } from 'vitest';
import { SUBJECTS } from '@ctem/contracts';
import type { PrismaService } from '@ctem/db';
import {
  SLA_MONITOR_TICK_MS,
  SlaMonitorService,
} from './sla-monitor.service';

const orgId = '11111111-1111-4111-8111-111111111111';
const findingId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const dueAt = new Date('2026-01-01T00:00:00.000Z');

const breached = { id: findingId, orgId, slaDueAt: dueAt };

function busStub() {
  const published: Array<{ subject: string; orgId: string; payload: unknown }> = [];
  return {
    published,
    bus: {
      publish: vi.fn(async (subject: string, oid: string, payload: unknown) => {
        published.push({ subject, orgId: oid, payload });
      }),
    },
  };
}

function prismaStub(opts: {
  rows?: Array<{ id: string; orgId: string; slaDueAt: Date }>;
  claim?: () => Promise<Array<{ id: string; slaDueAt: Date }>>;
}) {
  const rows = opts.rows ?? [breached];
  const queryRaw = opts.claim ?? (async () => [{ id: findingId, slaDueAt: dueAt }]);
  return {
    unsafeCrossTenant: vi.fn(async () => rows),
    withOrg: vi.fn(async (_org: string, fn: (tx: { $queryRaw: typeof queryRaw }) => unknown) =>
      fn({ $queryRaw: queryRaw }),
    ),
  };
}

describe('SlaMonitorService notify-once', () => {
  const services: SlaMonitorService[] = [];

  afterEach(async () => {
    await Promise.all(services.splice(0).map((svc) => svc.onModuleDestroy()));
  });

  it('keeps the ten-minute cadence', () => {
    const spy = vi.spyOn(global, 'setInterval');
    const { bus } = busStub();
    const svc = new SlaMonitorService(prismaStub({}) as unknown as PrismaService, bus as never);
    services.push(svc);
    svc.onApplicationBootstrap();
    expect(SLA_MONITOR_TICK_MS).toBe(10 * 60_000);
    expect(spy.mock.calls.some((call) => call[1] === SLA_MONITOR_TICK_MS)).toBe(true);
    spy.mockRestore();
  });

  it('publishes slaBreached on the first tick after a successful claim', async () => {
    const { bus, published } = busStub();
    const prisma = prismaStub({});
    const svc = new SlaMonitorService(prisma as unknown as PrismaService, bus as never);
    services.push(svc);

    await svc.runSweep();

    expect(prisma.withOrg).toHaveBeenCalledWith(orgId, expect.any(Function));
    expect(published).toEqual([
      {
        subject: SUBJECTS.slaBreached,
        orgId,
        payload: { findingId, dueAt },
      },
    ]);
  });

  it('does not publish on a second tick when the claim already lost', async () => {
    let claimed = false;
    const claim = async () => {
      if (claimed) return [];
      claimed = true;
      return [{ id: findingId, slaDueAt: dueAt }];
    };
    const { bus, published } = busStub();
    const prisma = prismaStub({ claim });
    const svc = new SlaMonitorService(prisma as unknown as PrismaService, bus as never);
    services.push(svc);

    await svc.runSweep();
    await svc.runSweep();

    expect(published).toHaveLength(1);
  });

  it('does not re-publish after a restart (new process, durable claim already held)', async () => {
    const { bus: firstBus, published: first } = busStub();
    const firstPrisma = prismaStub({
      claim: async () => [{ id: findingId, slaDueAt: dueAt }],
    });
    const firstSvc = new SlaMonitorService(firstPrisma as unknown as PrismaService, firstBus as never);
    services.push(firstSvc);
    await firstSvc.runSweep();
    expect(first).toHaveLength(1);

    const { bus: restartedBus, published: restarted } = busStub();
    const restartedPrisma = prismaStub({
      claim: async () => [],
    });
    const restartedSvc = new SlaMonitorService(
      restartedPrisma as unknown as PrismaService,
      restartedBus as never,
    );
    services.push(restartedSvc);
    await restartedSvc.runSweep();
    expect(restarted).toEqual([]);
  });

  it('lets only one of two replica sweeps publish for the same finding', async () => {
    let claimed = false;
    const claim = async () => {
      if (claimed) return [];
      claimed = true;
      return [{ id: findingId, slaDueAt: dueAt }];
    };
    const a = busStub();
    const b = busStub();
    const prismaA = prismaStub({ claim });
    const prismaB = prismaStub({ claim });
    const svcA = new SlaMonitorService(prismaA as unknown as PrismaService, a.bus as never);
    const svcB = new SlaMonitorService(prismaB as unknown as PrismaService, b.bus as never);
    services.push(svcA, svcB);

    await Promise.all([svcA.runSweep(), svcB.runSweep()]);

    expect(a.published.length + b.published.length).toBe(1);
    expect([...a.published, ...b.published][0]?.subject).toBe(SUBJECTS.slaBreached);
  });

  it('fails closed: a claim error skips the finding and does not publish', async () => {
    const { bus, published } = busStub();
    const prisma = prismaStub({
      claim: async () => {
        throw new Error('postgres unavailable');
      },
    });
    const svc = new SlaMonitorService(prisma as unknown as PrismaService, bus as never);
    services.push(svc);

    await svc.runSweep();

    expect(published).toEqual([]);
    expect(bus.publish).not.toHaveBeenCalled();
  });

  it('does not publish when the claim returns no row', async () => {
    const { bus, published } = busStub();
    const prisma = prismaStub({ claim: async () => [] });
    const svc = new SlaMonitorService(prisma as unknown as PrismaService, bus as never);
    services.push(svc);

    await svc.runSweep();

    expect(published).toEqual([]);
    expect(prisma.withOrg).toHaveBeenCalled();
  });
});

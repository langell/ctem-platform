import { randomUUID } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { CreateScanRequest, SCAN_KICK_EVENT, ScanKickMeterRecord, ScannerType } from '@ctem/contracts';
import { MemoryLeaseStore } from '@ctem/coordination';
import type { PrismaService } from '@ctem/db';
import { ScanDispatcherService, type DispatchAsset } from './scan-dispatcher.service';
import { ScanScheduleService } from './scan-schedule.service';
import type { ScanPlannerService } from './scan-planner.service';

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const USER_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

const assetA: DispatchAsset = {
  id: '22222222-2222-4222-8222-222222222222',
  kind: 'repository',
  externalKey: 'github:acme/api',
  attributes: { cloneUrl: 'https://github.com/acme/api' },
  integrationId: null,
};
const assetB: DispatchAsset = {
  id: '33333333-3333-4333-8333-333333333333',
  kind: 'repository',
  externalKey: 'github:acme/web',
  attributes: {},
  integrationId: null,
};

interface ScanRow {
  id: string;
  orgId: string;
  scannerType: string;
  trigger: string;
  status: string;
  requestedBy: string | null;
  jobsTotal: number;
  jobsCompleted: number;
  createdAt: Date;
  startedAt: Date | null;
  finishedAt: Date | null;
}

interface JobRow {
  id: string;
  orgId: string;
  scanId: string;
  assetId: string;
  scannerType: string;
  status: string;
  attempt: number;
  error: string | null;
}

interface KickRow {
  eventId: string;
  orgId: string;
  scanId: string;
  source: string;
  scannerTypes: string[];
  occurredAt: Date;
  idempotencyKey: string | null;
}

/**
 * Transactional stand-in: the callback mutates `state`, and a throw restores
 * the pre-callback snapshot. That is the same-commit bar for scan + scan.kick.
 */
function memoryDb(opts: { failKick?: boolean; assets?: DispatchAsset[] } = {}) {
  const assets = new Map((opts.assets ?? [assetA, assetB]).map((asset) => [asset.id, asset]));
  const state = {
    scans: [] as ScanRow[],
    jobs: [] as JobRow[],
    kicks: [] as KickRow[],
  };

  function txFor(orgId: string) {
    return {
      scan: {
        create: async ({ data }: { data: Omit<ScanRow, 'id' | 'createdAt' | 'jobsCompleted'> & { jobsCompleted?: number } }) => {
          if (data.orgId !== orgId) throw new Error('row-level security');
          const row: ScanRow = {
            jobsCompleted: 0,
            createdAt: new Date(),
            ...data,
            id: randomUUID(),
          };
          state.scans.push(row);
          return { ...row };
        },
        findUnique: async ({ where }: { where: { id: string } }) => {
          const row = state.scans.find((scan) => scan.id === where.id && scan.orgId === orgId);
          return row ? { ...row } : null;
        },
        findFirst: async ({
          where,
          select,
        }: {
          where?: { scannerType?: string; trigger?: string };
          select?: { createdAt?: boolean };
        }) => {
          const rows = state.scans
            .filter((scan) => scan.orgId === orgId)
            .filter((scan) => !where?.scannerType || scan.scannerType === where.scannerType)
            .filter((scan) => !where?.trigger || scan.trigger === where.trigger)
            .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
          const row = rows[0];
          if (!row) return null;
          if (select?.createdAt) return { createdAt: row.createdAt };
          return { ...row };
        },
        update: async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
          const row = state.scans.find((scan) => scan.id === where.id && scan.orgId === orgId);
          if (!row) throw new Error('scan missing');
          for (const [key, value] of Object.entries(data)) {
            if (value && typeof value === 'object' && 'increment' in value) {
              (row as unknown as Record<string, number>)[key] += (value as { increment: number }).increment;
            } else {
              (row as unknown as Record<string, unknown>)[key] = value;
            }
          }
          return { ...row };
        },
      },
      scanJob: {
        createMany: async ({ data }: { data: Array<Omit<JobRow, 'id' | 'attempt' | 'error'> & { attempt?: number }> }) => {
          for (const row of data) {
            if (row.orgId !== orgId) throw new Error('row-level security');
            state.jobs.push({ attempt: 1, error: null, id: randomUUID(), ...row });
          }
          return { count: data.length };
        },
        findMany: async ({ where }: { where?: { scanId?: string } }) =>
          state.jobs.filter((job) => job.orgId === orgId && (!where?.scanId || job.scanId === where.scanId)),
        update: async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
          const row = state.jobs.find((job) => job.id === where.id && job.orgId === orgId);
          if (!row) throw new Error('job missing');
          for (const [key, value] of Object.entries(data)) {
            if (value && typeof value === 'object' && 'increment' in value) {
              (row as unknown as Record<string, number>)[key] += (value as { increment: number }).increment;
            } else {
              (row as unknown as Record<string, unknown>)[key] = value;
            }
          }
          return { ...row };
        },
        count: async ({ where }: { where: { scanId: string; status?: string } }) =>
          state.jobs.filter(
            (job) => job.orgId === orgId && job.scanId === where.scanId && (!where.status || job.status === where.status),
          ).length,
      },
      scanKick: {
        findFirst: async ({ where }: { where: { orgId?: string; idempotencyKey?: string } }) => {
          const row = state.kicks.find(
            (kick) =>
              kick.orgId === orgId &&
              (!where.orgId || kick.orgId === where.orgId) &&
              kick.idempotencyKey === where.idempotencyKey,
          );
          return row ? { ...row } : null;
        },
        create: async ({ data }: { data: KickRow }) => {
          if (opts.failKick) throw new Error('meter insert failed');
          if (data.orgId !== orgId) throw new Error('row-level security');
          const duplicate =
            state.kicks.some((kick) => kick.eventId === data.eventId || kick.scanId === data.scanId) ||
            (data.idempotencyKey != null &&
              state.kicks.some((kick) => kick.orgId === data.orgId && kick.idempotencyKey === data.idempotencyKey));
          if (duplicate) {
            const err = new Error('Unique constraint failed') as Error & { code: string };
            err.code = 'P2002';
            throw err;
          }
          state.kicks.push({ ...data });
          return { ...data };
        },
      },
      asset: {
        findUniqueOrThrow: async ({ where }: { where: { id: string } }) => {
          const asset = assets.get(where.id);
          if (!asset) throw new Error(`asset ${where.id} missing`);
          return asset;
        },
      },
      integration: {
        findMany: async () => [],
      },
    };
  }

  const prisma = {
    user: {
      findUnique: async ({ where }: { where: { idpSubject: string } }) =>
        where.idpSubject === 'idp|known' ? { id: USER_ID } : null,
    },
    unsafeCrossTenant: async (_reason: string, fn: (db: unknown) => Promise<unknown>) =>
      fn({
        organization: {
          findMany: async () => [{ id: ORG_A }],
        },
      }),
    withOrg: async (orgId: string, fn: (tx: ReturnType<typeof txFor>) => Promise<unknown>) => {
      const snap = structuredClone(state);
      try {
        return await fn(txFor(orgId));
      } catch (err) {
        state.scans = snap.scans;
        state.jobs = snap.jobs;
        state.kicks = snap.kicks;
        throw err;
      }
    },
  };

  return { prisma, state, assets };
}

function harness(
  db: ReturnType<typeof memoryDb>,
  plan: DispatchAsset[] | (() => Promise<DispatchAsset[]>) = [assetA, assetB],
) {
  const published: unknown[] = [];
  const bus = {
    publish: vi.fn(async (_subject: string, _org: string, payload: unknown) => {
      published.push(payload);
    }),
  };
  const planner = {
    plan: vi.fn(async () => (typeof plan === 'function' ? plan() : plan)),
  };
  const dispatcher = new ScanDispatcherService(
    db.prisma as unknown as PrismaService,
    planner as unknown as ScanPlannerService,
    bus as never,
  );
  return { dispatcher, planner, bus, published };
}

const request = { scannerType: 'sca' as const, assetSelector: {}, options: {} };

describe('scan.kick meter', () => {
  it('emits one scan.kick on accept, not one per job', async () => {
    const db = memoryDb();
    const { dispatcher, bus } = harness(db);
    const created = await dispatcher.createScan(ORG_A, null, request, 'manual');
    expect(created.jobsDispatched).toBe(2);
    expect(bus.publish).toHaveBeenCalledTimes(2);
    expect(db.state.scans).toHaveLength(1);
    expect(db.state.kicks).toHaveLength(1);
    const kick = db.state.kicks[0]!;
    expect(kick.eventId).toBe(created.id);
    expect(kick.scanId).toBe(created.id);
    expect(kick.orgId).toBe(ORG_A);
    expect(kick.source).toBe('manual');
    expect(kick.scannerTypes).toEqual(['sca']);
    expect(kick.idempotencyKey).toBeNull();
    expect(ScanKickMeterRecord.parse({ ...kick, scannerTypes: kick.scannerTypes }).source).toBe('manual');
    expect(SCAN_KICK_EVENT).toBe('scan.kick');

    const again = await dispatcher.createScan(ORG_A, null, request, 'webhook');
    expect(again.id).not.toBe(created.id);
    expect(db.state.kicks).toHaveLength(2);
    expect(db.state.kicks[1]!.source).toBe('webhook');
  });

  it('returns the existing scan and does not emit a second kick for a duplicate idempotency key', async () => {
    const db = memoryDb();
    const { dispatcher, bus } = harness(db);
    const first = await dispatcher.createScan(ORG_A, null, { ...request, externalId: 'ci-run-9' }, 'ci');
    const second = await dispatcher.createScan(ORG_A, null, { ...request, externalId: 'ci-run-9' }, 'ci', 'ci-run-9');
    expect(second.id).toBe(first.id);
    expect(db.state.kicks).toHaveLength(1);
    expect(db.state.kicks[0]!.source).toBe('ci');
    expect(db.state.kicks[0]!.idempotencyKey).toBe('ci-run-9');
    expect(bus.publish).toHaveBeenCalledTimes(2);

    const otherOrg = await dispatcher.createScan(ORG_B, null, { ...request, externalId: 'ci-run-9' }, 'ci');
    expect(otherOrg.id).not.toBe(first.id);
    expect(db.state.kicks).toHaveLength(2);
    expect(db.state.kicks.every((kick) => kick.idempotencyKey === 'ci-run-9')).toBe(true);
  });

  it('treats a lost race on the idempotency unique index as a replay', async () => {
    const winnerId = '44444444-4444-4444-8444-444444444444';
    const winner = { id: winnerId, orgId: ORG_A, status: 'running', scannerType: 'sca' };
    let inserts = 0;
    const tx = {
      scanKick: {
        findFirst: vi.fn(async () =>
          inserts > 0 ? { eventId: winnerId, scanId: winnerId, orgId: ORG_A, idempotencyKey: 'race' } : null,
        ),
        create: vi.fn(async () => {
          inserts += 1;
          const err = new Error('Unique constraint failed') as Error & { code: string };
          err.code = 'P2002';
          throw err;
        }),
      },
      scan: {
        create: vi.fn(async () => ({ id: randomUUID(), status: 'running' })),
        findUnique: vi.fn(async () => winner),
      },
      scanJob: {
        createMany: vi.fn(),
        findMany: vi.fn(async () => []),
      },
    };
    const prisma = {
      withOrg: vi.fn(async (_org: string, fn: (client: typeof tx) => Promise<unknown>) => fn(tx)),
      user: { findUnique: vi.fn(async () => null) },
    };
    const bus = { publish: vi.fn() };
    const dispatcher = new ScanDispatcherService(
      prisma as unknown as PrismaService,
      { plan: vi.fn(async () => []) } as unknown as ScanPlannerService,
      bus as never,
    );
    const result = await dispatcher.createScan(ORG_A, null, request, 'manual', 'race');
    expect(result.id).toBe(winnerId);
    expect(tx.scanKick.create).toHaveBeenCalledTimes(1);
    expect(bus.publish).not.toHaveBeenCalled();
  });

  it('emits one scan.kick when a schedule tick runs twice, including two replicas', async () => {
    const soloDb = memoryDb({ assets: [] });
    const solo = new ScanScheduleService(
      soloDb.prisma as unknown as PrismaService,
      harness(soloDb, []).dispatcher,
      new MemoryLeaseStore(),
    );
    await solo.runScheduledTick();
    const once = soloDb.state.kicks.length;
    expect(once).toBe(ScannerType.options.length);
    expect(soloDb.state.kicks.every((kick) => kick.source === 'schedule')).toBe(true);
    await solo.runScheduledTick();
    expect(soloDb.state.kicks).toHaveLength(once);
    await solo.onModuleDestroy();

    const sharedDb = memoryDb({ assets: [] });
    const store = new MemoryLeaseStore();
    const dispatcher = harness(sharedDb, []).dispatcher;
    const a = new ScanScheduleService(sharedDb.prisma as unknown as PrismaService, dispatcher, store);
    const b = new ScanScheduleService(sharedDb.prisma as unknown as PrismaService, dispatcher, store);
    await Promise.all([a.runScheduledTick(), b.runScheduledTick()]);
    expect(sharedDb.state.kicks).toHaveLength(once);
    await Promise.all([a.onModuleDestroy(), b.onModuleDestroy()]);
  });

  it('does not emit another scan.kick when a job is retried', async () => {
    const db = memoryDb();
    const { dispatcher, bus } = harness(db, [assetA]);
    await dispatcher.createScan(ORG_A, null, request);
    expect(db.state.kicks).toHaveLength(1);
    const jobId = db.state.jobs[0]!.id;
    await dispatcher.retryJob(ORG_A, jobId);
    expect(db.state.kicks).toHaveLength(1);
    expect(db.state.scans).toHaveLength(1);
    expect(bus.publish).toHaveBeenCalledTimes(2);
  });

  it('emits nothing when authz, validation, or the idempotency key fails before persist', async () => {
    expect(() => CreateScanRequest.parse({ scannerType: 'sca', conclusion: 'failed' })).toThrow();
    expect(CreateScanRequest.parse({ scannerType: 'sca', external_id: 'pipe-1' })).toMatchObject({
      externalId: 'pipe-1',
    });
    expect(() =>
      CreateScanRequest.parse({ scannerType: 'sca', externalId: 'a', external_id: 'b' }),
    ).toThrow(/disagree/);

    const db = memoryDb();
    const { dispatcher, planner } = harness(db);
    await expect(
      dispatcher.createScan(ORG_A, 'idp|unknown', request),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      dispatcher.createScan(ORG_A, null, { ...request, externalId: 'one' }, 'manual', 'two'),
    ).rejects.toBeInstanceOf(BadRequestException);
    planner.plan.mockRejectedValueOnce(new Error('selector invalid'));
    await expect(dispatcher.createScan(ORG_A, null, request)).rejects.toThrow(/selector invalid/);
    expect(db.state.scans).toHaveLength(0);
    expect(db.state.kicks).toHaveLength(0);
  });

  it('keeps the scan.kick when dispatch fails after the scan commit', async () => {
    const db = memoryDb();
    const bus = {
      publish: vi.fn(async () => {
        throw new Error('JetStream not initialized');
      }),
    };
    const failing = new ScanDispatcherService(
      db.prisma as unknown as PrismaService,
      { plan: vi.fn(async () => [assetA]) } as unknown as ScanPlannerService,
      bus as never,
    );
    await expect(failing.createScan(ORG_A, null, request)).resolves.toMatchObject({ jobsDispatched: 1 });
    expect(db.state.scans).toHaveLength(1);
    expect(db.state.kicks).toHaveLength(1);
    expect(db.state.jobs[0]!.status).toBe('failed');
  });

  it('rolls the scan back when the meter insert fails in the same transaction', async () => {
    const db = memoryDb({ failKick: true });
    const { dispatcher } = harness(db, [assetA]);
    await expect(dispatcher.createScan(ORG_A, null, request)).rejects.toThrow(/meter insert failed/);
    expect(db.state.scans).toHaveLength(0);
    expect(db.state.jobs).toHaveLength(0);
    expect(db.state.kicks).toHaveLength(0);
  });
});

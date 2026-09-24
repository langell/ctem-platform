import 'reflect-metadata';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { describe, expect, it, vi } from 'vitest';
import {
  InternalAuthGuard,
  PRINCIPAL_HEADER,
  PRINCIPAL_SIGNATURE_HEADER,
  encodePrincipal,
} from '@ctem/auth';
import { ListScanKicksQuery, SCAN_KICK_EVENT, type Permission } from '@ctem/contracts';
import { ZodQuery } from '@ctem/service-kit';
import type { PrismaService } from '@ctem/db';
import { ScanKickMeterService } from './scan-kick-meter.service';
import { ScanKicksController } from './scan-kicks.controller';
import { encodeScanKickCursor } from './scan-kick-meter.query';

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const NOW = new Date('2026-09-24T12:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;

function eventId(n: number): string {
  return `aaaaaaaa-aaaa-4aaa-8aaa-${n.toString(16).padStart(12, '0')}`;
}

interface Kick {
  eventId: string;
  orgId: string;
  scanId: string;
  source: string;
  scannerTypes: string[];
  occurredAt: Date;
}

function kick(partial: Partial<Kick> & Pick<Kick, 'eventId' | 'orgId' | 'occurredAt'>): Kick {
  return {
    scanId: partial.eventId,
    source: 'manual',
    scannerTypes: ['sca'],
    ...partial,
  };
}

type Where = {
  AND?: Where[];
  OR?: Where[];
  source?: string;
  occurredAt?: { gte?: Date; lt?: Date } | Date;
  eventId?: { lt: string };
};

function matches(row: Kick, where: Where | undefined): boolean {
  if (!where) return true;
  if (where.AND) return where.AND.every((part) => matches(row, part));
  if (where.OR) return where.OR.some((part) => matches(row, part));
  if (where.source !== undefined && row.source !== where.source) return false;
  if (where.occurredAt instanceof Date) {
    if (row.occurredAt.getTime() !== where.occurredAt.getTime()) return false;
  } else if (where.occurredAt) {
    if (where.occurredAt.gte && row.occurredAt.getTime() < where.occurredAt.gte.getTime())
      return false;
    if (where.occurredAt.lt && row.occurredAt.getTime() >= where.occurredAt.lt.getTime())
      return false;
  }
  if (where.eventId?.lt && row.eventId >= where.eventId.lt) return false;
  return true;
}

function byDesc(a: Kick, b: Kick): number {
  const time = b.occurredAt.getTime() - a.occurredAt.getTime();
  if (time !== 0) return time;
  return a.eventId < b.eventId ? 1 : a.eventId > b.eventId ? -1 : 0;
}

/**
 * RLS stand-in: `withOrg` only sees that org's rows. A query that forgets
 * `withOrg` has no `scanKick` client, so it cannot accidentally read the table.
 */
function memoryDb(rows: Kick[]) {
  const calls: string[] = [];
  let lastTake: number | undefined;
  let lastOrderBy: unknown;
  const prisma = {
    withOrg: vi.fn(async (orgId: string, fn: (tx: unknown) => Promise<unknown>) => {
      calls.push(orgId);
      const visible = () => rows.filter((row) => row.orgId === orgId);
      const tx = {
        scanKick: {
          count: async ({ where }: { where?: Where }) =>
            visible().filter((row) => matches(row, where)).length,
          findMany: async ({
            where,
            take,
            orderBy,
          }: {
            where?: Where;
            take?: number;
            orderBy?: unknown;
          }) => {
            lastTake = take;
            lastOrderBy = orderBy;
            const page = visible()
              .filter((row) => matches(row, where))
              .sort(byDesc);
            return (take === undefined ? page : page.slice(0, take)).map((row) => ({ ...row }));
          },
        },
      };
      return fn(tx);
    }),
  };
  return {
    prisma: prisma as unknown as PrismaService,
    calls,
    take: () => lastTake,
    orderBy: () => lastOrderBy,
  };
}

function query(input: Record<string, unknown> = {}): ListScanKicksQuery {
  return ListScanKicksQuery.parse(input);
}

describe('scan.kick meter read', () => {
  const inside = kick({
    eventId: eventId(1),
    orgId: ORG_A,
    occurredAt: new Date(NOW.getTime() - 1 * DAY),
    source: 'manual',
  });
  const older = kick({
    eventId: eventId(2),
    orgId: ORG_A,
    occurredAt: new Date(NOW.getTime() - 31 * DAY),
    source: 'ci',
  });
  const otherOrg = kick({
    eventId: eventId(3),
    orgId: ORG_B,
    occurredAt: new Date(NOW.getTime() - 1 * DAY),
    source: 'manual',
    scannerTypes: ['sast'],
  });

  it('hides other orgs, including when the query names their orgId', async () => {
    const db = memoryDb([inside, older, otherOrg]);
    const svc = new ScanKickMeterService(db.prisma);
    const page = await svc.list(
      ORG_A,
      query({ orgId: ORG_B, from: '2020-01-01T00:00:00.000Z' }),
      NOW,
    );

    expect(db.calls).toEqual([ORG_A]);
    expect(page.event).toBe(SCAN_KICK_EVENT);
    expect(page.total).toBe(2);
    expect(page.items.map((item) => item.eventId)).toEqual([inside.eventId, older.eventId]);
    expect(page.items.every((item) => item.orgId === ORG_A)).toBe(true);
    expect(page).not.toHaveProperty('price');
    expect(page).not.toHaveProperty('currency');
    expect(page).not.toHaveProperty('remainingCredits');
  });

  it('does not 500 when the cursor names another org event', async () => {
    const db = memoryDb([inside, otherOrg]);
    const svc = new ScanKickMeterService(db.prisma);
    const page = await svc.list(
      ORG_A,
      query({
        from: '2020-01-01T00:00:00.000Z',
        cursor: encodeScanKickCursor(otherOrg),
      }),
      NOW,
    );
    expect(page.items.map((item) => item.orgId)).toEqual([ORG_A]);
    expect(page.total).toBe(1);
  });

  it('returns an empty list for an org with no kicks', async () => {
    const db = memoryDb([otherOrg]);
    const svc = new ScanKickMeterService(db.prisma);
    const page = await svc.list(ORG_A, query({ from: '2020-01-01T00:00:00.000Z' }), NOW);
    expect(page).toEqual({ event: SCAN_KICK_EVENT, total: 0, items: [], nextCursor: null });
    expect(db.calls).toEqual([ORG_A]);
  });

  it('defaults to the last 30 days when neither from nor to is set', async () => {
    const onBound = kick({
      eventId: eventId(4),
      orgId: ORG_A,
      occurredAt: new Date(NOW.getTime() - 30 * DAY),
      source: 'schedule',
    });
    const justBefore = kick({
      eventId: eventId(5),
      orgId: ORG_A,
      occurredAt: new Date(NOW.getTime() - 30 * DAY - 1),
      source: 'schedule',
    });
    const db = memoryDb([inside, justBefore, onBound]);
    const svc = new ScanKickMeterService(db.prisma);
    const page = await svc.list(ORG_A, query(), NOW);
    expect(page.items.map((item) => item.eventId).sort()).toEqual(
      [inside.eventId, onBound.eventId].sort(),
    );
    expect(page.total).toBe(2);
  });

  it('treats from as inclusive and to as exclusive, and skips the 30d default when either is set', async () => {
    const atFrom = kick({
      eventId: eventId(6),
      orgId: ORG_A,
      occurredAt: new Date('2026-01-01T00:00:00.000Z'),
      source: 'webhook',
    });
    const atTo = kick({
      eventId: eventId(7),
      orgId: ORG_A,
      occurredAt: new Date('2026-02-01T00:00:00.000Z'),
      source: 'webhook',
    });
    const between = kick({
      eventId: eventId(8),
      orgId: ORG_A,
      occurredAt: new Date('2026-01-15T00:00:00.000Z'),
      source: 'api',
    });
    const db = memoryDb([atFrom, atTo, between, inside]);
    const svc = new ScanKickMeterService(db.prisma);

    const ranged = await svc.list(
      ORG_A,
      query({ from: '2026-01-01T00:00:00.000Z', to: '2026-02-01T00:00:00.000Z' }),
      NOW,
    );
    expect(ranged.total).toBe(2);
    expect(ranged.items.map((item) => item.eventId)).toEqual([between.eventId, atFrom.eventId]);

    const sourceOnly = await svc.list(
      ORG_A,
      query({ from: '2026-01-01T00:00:00.000Z', to: '2026-02-01T00:00:00.000Z', source: 'api' }),
      NOW,
    );
    expect(sourceOnly.items.map((item) => item.eventId)).toEqual([between.eventId]);

    const fromOnly = await svc.list(ORG_A, query({ from: '2026-01-01T00:00:00.000Z' }), NOW);
    expect(fromOnly.items.map((item) => item.eventId)).toContain(atFrom.eventId);
    expect(fromOnly.items.map((item) => item.eventId)).toContain(inside.eventId);
  });

  it('caps limit at 200 and pages with an opaque (occurredAt, eventId) cursor', async () => {
    const sameTime = new Date('2026-09-20T00:00:00.000Z');
    const rows = [1, 2, 3].map((n) =>
      kick({ eventId: eventId(n), orgId: ORG_A, occurredAt: sameTime, source: 'ci' }),
    );
    const db = memoryDb(rows);
    const svc = new ScanKickMeterService(db.prisma);

    const first = await svc.list(ORG_A, query({ from: '2026-09-01', limit: '999' }), NOW);
    expect(db.take()).toBe(201);
    expect(db.orderBy()).toEqual([{ occurredAt: 'desc' }, { eventId: 'desc' }]);
    expect(first.total).toBe(3);
    expect(first.items).toHaveLength(3);
    expect(first.nextCursor).toBeNull();

    const page = await svc.list(ORG_A, query({ from: '2026-09-01', limit: '2' }), NOW);
    expect(page.items.map((item) => item.eventId)).toEqual([eventId(3), eventId(2)]);
    expect(page.nextCursor).toEqual(encodeScanKickCursor(page.items[1]!));
    expect(page.total).toBe(3);

    const next = await svc.list(
      ORG_A,
      query({ from: '2026-09-01', limit: '2', cursor: page.nextCursor ?? '' }),
      NOW,
    );
    expect(next.items.map((item) => item.eventId)).toEqual([eventId(1)]);
    expect(next.nextCursor).toBeNull();
    expect(next.total).toBe(3);
  });

  it('400s an invalid cursor and does not query', async () => {
    const db = memoryDb([inside]);
    const svc = new ScanKickMeterService(db.prisma);
    await expect(svc.list(ORG_A, query({ cursor: 'not-a-cursor' }), NOW)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(db.calls).toEqual([]);
  });

  it('returns an empty page when from is not before to', async () => {
    const db = memoryDb([inside]);
    const svc = new ScanKickMeterService(db.prisma);
    const page = await svc.list(
      ORG_A,
      query({ from: '2026-09-10T00:00:00.000Z', to: '2026-09-01T00:00:00.000Z' }),
      NOW,
    );
    expect(page).toEqual({ event: SCAN_KICK_EVENT, total: 0, items: [], nextCursor: null });
    expect(db.calls).toEqual([]);
  });
});

describe('scan.kick meter authz', () => {
  it('rejects a query orgId before the service runs and requires scan:read', async () => {
    const list = vi.fn(async () => ({
      event: SCAN_KICK_EVENT,
      total: 0,
      items: [],
      nextCursor: null,
    }));
    const ctrl = new ScanKicksController({ list } as unknown as ScanKickMeterService);
    const parsed = new ZodQuery(ListScanKicksQuery).transform({ orgId: ORG_B, source: 'webhook' });
    expect(parsed).not.toHaveProperty('orgId');
    await ctrl.list(ORG_A, parsed);
    expect(list).toHaveBeenCalledWith(ORG_A, parsed);

    expect(() => new ZodQuery(ListScanKicksQuery).transform({ source: 'billing' })).toThrow(
      BadRequestException,
    );

    const guard = new InternalAuthGuard(new Reflector());
    expect(() => guard.canActivate(contextFor(ScanKicksController, ['finding:read']))).toThrow(
      ForbiddenException,
    );
    expect(guard.canActivate(contextFor(ScanKicksController, ['scan:read']))).toBe(true);

    const app = readFileSync(resolve('apps/orchestrator-service/src/app.module.ts'), 'utf8');
    expect(app).toMatch(/ScanKicksController/);
    expect(app).toMatch(/ScanKickMeterService/);
  });
});

function contextFor(cls: { prototype: { list: () => unknown } }, permissions: Permission[]) {
  const encoded = encodePrincipal({
    userId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    orgId: ORG_A,
    role: 'developer',
    permissions,
    serviceAccount: null,
    traceId: 'trace-meter',
  });
  const req = {
    headers: {
      [PRINCIPAL_HEADER]: encoded.value,
      [PRINCIPAL_SIGNATURE_HEADER]: encoded.signature,
    },
  };
  return {
    getHandler: () => cls.prototype.list,
    getClass: () => cls,
    switchToHttp: () => ({ getRequest: () => req }),
  } as never;
}

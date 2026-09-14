import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { SUBJECTS } from '@ctem/contracts';
import { PrismaService, type PrismaClient } from '@ctem/db';
import type { EventBus } from '@ctem/events';
import { createAsset, createFinding, createOrg, deleteOrgCascade, ownerClient } from '@ctem/testing';
import { SlaMonitorService } from './sla-monitor.service';

/**
 * Notify-once against real Postgres as `ctem_app`. Listing uses the owner
 * connection because the existing unsafeCrossTenant sweep is the platform
 * escape hatch; claims are org-scoped withOrg UPDATEs under RLS.
 */
describe('SlaMonitorService notify-once (integration)', () => {
  let owner: PrismaClient;
  let app: PrismaService;
  let orgId: string;
  let assetId: string;

  beforeAll(async () => {
    owner = ownerClient();
    app = new PrismaService();
    orgId = (await createOrg(owner)).id;
    assetId = (await createAsset(owner, orgId)).id;
  });

  afterAll(async () => {
    await deleteOrgCascade(owner, orgId);
    await Promise.all([owner.$disconnect(), app.$disconnect()]);
  });

  async function openBreach(fingerprint: string) {
    return createFinding(owner, orgId, assetId, {
      fingerprint,
      state: 'open',
      resolvedAt: null,
      slaDueAt: new Date(Date.now() - 60_000),
      slaNotifiedAt: null,
    });
  }

  function monitor() {
    const published: Array<{ subject: string; orgId: string; payload: unknown }> = [];
    const bus = {
      publish: vi.fn(async (subject: string, oid: string, payload: unknown) => {
        published.push({ subject, orgId: oid, payload });
      }),
    } as unknown as EventBus;
    const prisma = {
      unsafeCrossTenant: async () =>
        owner.finding.findMany({
          where: {
            orgId,
            slaDueAt: { lt: new Date() },
            resolvedAt: null,
            state: { in: ['open', 'triaged', 'in_progress'] },
            slaNotifiedAt: null,
          },
          select: { id: true, orgId: true, slaDueAt: true },
          take: 5_000,
        }),
      withOrg: (oid: string, fn: Parameters<PrismaService['withOrg']>[1]) => app.withOrg(oid, fn),
    };
    return {
      published,
      service: new SlaMonitorService(prisma as unknown as PrismaService, bus),
    };
  }

  it('publishes once on the first sweep and not again on the second', async () => {
    const finding = await openBreach('sla-int-second-tick');
    const { service, published } = monitor();

    await service.runSweep();
    await service.runSweep();

    const ours = published.filter(
      (e) => e.subject === SUBJECTS.slaBreached && (e.payload as { findingId: string }).findingId === finding.id,
    );
    expect(ours).toHaveLength(1);
    expect(ours[0]?.orgId).toBe(orgId);

    const row = await owner.finding.findUniqueOrThrow({ where: { id: finding.id } });
    expect(row.slaNotifiedAt).not.toBeNull();
  });

  it('does not re-publish after a process restart once the column is claimed', async () => {
    const finding = await openBreach('sla-int-restart');
    const first = monitor();
    await first.service.runSweep();
    expect(
      first.published.some(
        (e) =>
          e.subject === SUBJECTS.slaBreached &&
          (e.payload as { findingId: string }).findingId === finding.id,
      ),
    ).toBe(true);

    const restarted = monitor();
    await restarted.service.runSweep();
    expect(
      restarted.published.some(
        (e) => (e.payload as { findingId: string }).findingId === finding.id,
      ),
    ).toBe(false);
  });

  it('lets only one of two concurrent replica sweeps publish', async () => {
    const finding = await openBreach('sla-int-two-replica');
    const a = monitor();
    const b = monitor();

    await Promise.all([a.service.runSweep(), b.service.runSweep()]);

    const hits = [...a.published, ...b.published].filter(
      (e) =>
        e.subject === SUBJECTS.slaBreached &&
        (e.payload as { findingId: string }).findingId === finding.id,
    );
    expect(hits).toHaveLength(1);

    const row = await owner.finding.findUniqueOrThrow({ where: { id: finding.id } });
    expect(row.slaNotifiedAt).not.toBeNull();
  });

  it('re-arms after resolve so a later sweep can claim a new window', async () => {
    const finding = await openBreach('sla-int-reset-resolve');
    const first = monitor();
    await first.service.runSweep();
    expect(
      first.published.filter((e) => (e.payload as { findingId: string }).findingId === finding.id),
    ).toHaveLength(1);

    await owner.finding.update({
      where: { id: finding.id },
      data: { state: 'resolved', resolvedAt: new Date(), slaNotifiedAt: null },
    });
    await owner.finding.update({
      where: { id: finding.id },
      data: {
        state: 'open',
        resolvedAt: null,
        slaDueAt: new Date(Date.now() - 30_000),
      },
    });

    const second = monitor();
    await second.service.runSweep();
    expect(
      second.published.filter((e) => (e.payload as { findingId: string }).findingId === finding.id),
    ).toHaveLength(1);
  });
});

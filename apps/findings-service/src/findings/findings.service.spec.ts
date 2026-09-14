import { randomUUID } from 'node:crypto';
import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import { SUBJECTS, type FindingsReportedPayload, type RawFinding } from '@ctem/contracts';
import { FindingNormalizer } from './finding-normalizer';
import { FindingsService } from './findings.service';

const ORG_B = 'bbbbbbbb-2222-4333-8444-555566667777';
const FINDING_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

function raw(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    externalId: 'CVE-2024-0001',
    scannerType: 'sca',
    scannerName: 'ctem-sca',
    title: 'CVE-2024-0001 in lodash@4.17.21',
    description: '',
    severity: 'high',
    identifiers: [{ system: 'CVE', value: 'CVE-2024-0001' }],
    cvssVector: null,
    cvssScore: 7.5,
    epssScore: null,
    kev: false,
    location: { purl: 'pkg:npm/lodash@4.17.21' },
    fix: { available: false },
    evidence: {},
    raw: {},
    ...overrides,
  } as RawFinding;
}

function payload(findings: RawFinding[]): FindingsReportedPayload {
  return {
    scanId: randomUUID(),
    jobId: randomUUID(),
    assetId: randomUUID(),
    scannerType: 'sca',
    artifactKey: null,
    findings,
  };
}

function service() {
  const upserts: Array<{
    where: { orgId_fingerprint: { fingerprint: string } };
    create: {
      location: Record<string, unknown>;
      evidence: Record<string, unknown>;
      fingerprint: string;
      validation?: string;
      kev?: boolean;
    };
    update: {
      location: Record<string, unknown>;
      evidence: Record<string, unknown>;
      validation?: string;
      kev?: boolean;
    };
  }> = [];

  const byFingerprint = new Map<string, Record<string, unknown>>();

  const tx = {
    finding: {
      findUnique: vi.fn(
        async (args: { where: { id?: string; orgId_fingerprint?: { fingerprint: string } } }) => {
          if (args.where.orgId_fingerprint) {
            return byFingerprint.get(args.where.orgId_fingerprint.fingerprint) ?? null;
          }
          return null;
        },
      ),
      upsert: vi.fn(async (args: (typeof upserts)[number]) => {
        upserts.push(args);
        const fp = args.where.orgId_fingerprint.fingerprint;
        const existing = byFingerprint.get(fp);
        const row = existing
          ? { ...existing, ...args.update }
          : { id: randomUUID(), validation: 'not_validated', ...args.create };
        byFingerprint.set(fp, row);
        return row;
      }),
      updateMany: vi.fn(async () => ({ count: 0 })),
      update: vi.fn(async (args: { where: { id: string }; data: Record<string, unknown> }) => ({
        id: args.where.id,
        state: args.data.state,
        slaNotifiedAt: args.data.slaNotifiedAt ?? new Date(),
      })),
      findUniqueOrThrow: vi.fn(async () => ({ id: FINDING_A, state: 'open' })),
    },
    findingEvent: { create: vi.fn(async () => ({})) },
  };

  const prisma = {
    withOrg: vi.fn(async (_org: string, fn: (client: typeof tx) => Promise<unknown>) => fn(tx)),
  };

  const bus = { publish: vi.fn(async () => undefined) } as unknown as EventBus;
  const findings = new FindingsService(prisma as never, bus, new FindingNormalizer());
  return { findings, upserts, tx, bus, byFingerprint };
}

describe('FindingsService.ingest persist', () => {
  const orgId = randomUUID();

  it('persists one finding with both lockfile paths when one scan reports the same purl twice', async () => {
    const { findings, upserts } = service();
    const batch = payload([
      raw({
        location: { purl: 'pkg:npm/lodash@4.17.21', path: 'app-a/package-lock.json' },
        evidence: { dependencyPath: ['lodash'] },
      }),
      raw({
        location: { purl: 'pkg:npm/lodash@4.17.21', path: 'app-b/package-lock.json' },
        evidence: { dependencyPath: ['express', 'lodash'] },
      }),
    ]);

    await findings.ingest(orgId, batch);

    expect(upserts).toHaveLength(1);
    expect(upserts[0].create.location.path).toEqual([
      'app-a/package-lock.json',
      'app-b/package-lock.json',
    ]);
    expect(upserts[0].create.evidence.dependencyPath).toEqual([
      ['lodash'],
      ['express', 'lodash'],
    ]);
    expect(upserts[0].update.location.path).toEqual(upserts[0].create.location.path);
    expect(upserts[0].update.evidence.dependencyPath).toEqual(upserts[0].create.evidence.dependencyPath);
  });

  it('persists two findings when the same scan reports different purls', async () => {
    const { findings, upserts } = service();
    await findings.ingest(
      orgId,
      payload([
        raw({ location: { purl: 'pkg:npm/lodash@4.17.21', path: 'app-a/package-lock.json' } }),
        raw({
          identifiers: [{ system: 'CVE', value: 'CVE-2024-0002' }],
          location: { purl: 'pkg:npm/qs@6.5.2', path: 'app-a/package-lock.json' },
        }),
      ]),
    );

    expect(upserts).toHaveLength(2);
    expect(upserts.map((row) => row.create.location.purl).sort()).toEqual([
      'pkg:npm/lodash@4.17.21',
      'pkg:npm/qs@6.5.2',
    ]);
    expect(upserts[0].create.fingerprint).not.toBe(upserts[1].create.fingerprint);
  });

  it('writes the same fingerprint key for two lockfiles of one purl', async () => {
    const { findings, upserts } = service();
    const normalizer = new FindingNormalizer();
    const batch = payload([
      raw({ location: { purl: 'pkg:npm/lodash@4.17.21', path: 'app-a/package-lock.json' } }),
      raw({ location: { purl: 'pkg:npm/lodash@4.17.21', path: 'app-b/package-lock.json' } }),
    ]);

    await findings.ingest(orgId, batch);

    expect(upserts).toHaveLength(1);
    expect(upserts[0].create.fingerprint).toBe(normalizer.fingerprint(batch.assetId, batch.findings[0]));
    expect(upserts[0].create.fingerprint).toBe(normalizer.fingerprint(batch.assetId, batch.findings[1]));
  });
});

describe('FindingsService.get', () => {
  it('returns 404 when the finding is absent in the org (including RLS miss)', async () => {
    const { findings, tx } = service();
    await expect(findings.get(ORG_B, FINDING_A)).rejects.toBeInstanceOf(NotFoundException);
    expect(tx.finding.findUnique).toHaveBeenCalledWith({
      where: { id: FINDING_A },
      include: { events: true, asset: true },
    });
  });
});

describe('FindingsService.ingest validation promotion', () => {
  const orgId = randomUUID();

  it('reachable + KEV → exploitable', async () => {
    const { findings, upserts } = service();
    await findings.ingest(
      orgId,
      payload([raw({ kev: true, evidence: { reachability: 'reachable' } })]),
    );
    expect(upserts[0].create.validation).toBe('exploitable');
    expect(upserts[0].update.validation).toBe('exploitable');
  });

  it('reachable alone → reachable', async () => {
    const { findings, upserts } = service();
    await findings.ingest(orgId, payload([raw({ evidence: { reachability: 'reachable' } })]));
    expect(upserts[0].create.validation).toBe('reachable');
  });

  it('not_reachable → not_reachable', async () => {
    const { findings, upserts } = service();
    await findings.ingest(orgId, payload([raw({ kev: true, evidence: { reachability: 'not_reachable' } })]));
    expect(upserts[0].create.validation).toBe('not_reachable');
  });

  it('unknown → not_validated (does not write a verdict)', async () => {
    const { findings, upserts, byFingerprint } = service();
    await findings.ingest(orgId, payload([raw({ kev: true, evidence: { reachability: 'unknown' } })]));
    expect(upserts[0].create.validation).toBeUndefined();
    expect([...byFingerprint.values()][0]?.validation).toBe('not_validated');
  });

  it('non-SCA findings stay not_validated even with reachable evidence', async () => {
    const { findings, upserts } = service();
    for (const scannerType of ['sast', 'asm', 'cloud_posture', 'container', 'iac'] as const) {
      upserts.length = 0;
      await findings.ingest(
        orgId,
        payload([
          raw({
            scannerType,
            scannerName: `ctem-${scannerType}`,
            evidence: { reachability: 'reachable' },
            kev: true,
          }),
        ]),
      );
      expect(upserts[0].create.validation, scannerType).toBeUndefined();
    }
  });

  it('re-ingest with the same reachability does not flap', async () => {
    const { findings, upserts, byFingerprint } = service();
    const batch = payload([raw({ evidence: { reachability: 'reachable' } })]);
    await findings.ingest(orgId, batch);
    await findings.ingest(orgId, batch);
    expect(upserts).toHaveLength(2);
    expect(upserts[0].create.validation).toBe('reachable');
    expect(upserts[1].update.validation).toBe('reachable');
    expect([...byFingerprint.values()][0]?.validation).toBe('reachable');
  });

  it('KEV flip on re-ingest re-evaluates reachable → exploitable', async () => {
    const { findings, upserts } = service();
    const assetId = randomUUID();
    const scan = (kev: boolean): FindingsReportedPayload => ({
      scanId: randomUUID(),
      jobId: randomUUID(),
      assetId,
      scannerType: 'sca',
      artifactKey: null,
      findings: [raw({ kev, evidence: { reachability: 'reachable' } })],
    });
    await findings.ingest(orgId, scan(false));
    await findings.ingest(orgId, scan(true));
    expect(upserts[0].create.validation).toBe('reachable');
    expect(upserts[1].update.validation).toBe('exploitable');
    expect(upserts[1].update.kev).toBe(true);
  });

  it('unknown re-ingest leaves a prior reachable verdict', async () => {
    const { findings, upserts, byFingerprint } = service();
    const assetId = randomUUID();
    const scan = (reachability: string): FindingsReportedPayload => ({
      scanId: randomUUID(),
      jobId: randomUUID(),
      assetId,
      scannerType: 'sca',
      artifactKey: null,
      findings: [raw({ evidence: { reachability } })],
    });
    await findings.ingest(orgId, scan('reachable'));
    await findings.ingest(orgId, scan('unknown'));
    expect(upserts[1].update.validation).toBeUndefined();
    expect([...byFingerprint.values()][0]?.validation).toBe('reachable');
  });

  it('still requests a risk rescore after validation is written', async () => {
    const { findings, bus } = service();
    await findings.ingest(orgId, payload([raw({ kev: true, evidence: { reachability: 'reachable' } })]));
    const published = vi.mocked(bus.publish).mock.calls.map((c) => c[0]);
    expect(published).toContain(SUBJECTS.findingCreated);
    expect(published).toContain(SUBJECTS.riskRescoreRequested);
  });
});

describe('FindingsService SLA notify claim reset', () => {
  const orgId = randomUUID();

  it('clears slaNotifiedAt on triage to resolved', async () => {
    const { findings, tx } = service();
    tx.finding.findUniqueOrThrow = vi.fn(async () => ({
      id: FINDING_A,
      state: 'open',
      slaNotifiedAt: new Date(),
    }));
    await findings.triage(orgId, FINDING_A, 'actor-1', {
      state: 'resolved',
      reason: 'fixed in 1.2.3',
    });
    expect(tx.finding.update).toHaveBeenCalledWith({
      where: { id: FINDING_A },
      data: expect.objectContaining({ state: 'resolved', slaNotifiedAt: null }),
    });
  });

  it('clears slaNotifiedAt on ingest auto-resolve', async () => {
    const { findings, tx } = service();
    await findings.ingest(orgId, payload([raw()]));
    expect(tx.finding.updateMany).toHaveBeenCalledWith({
      where: expect.objectContaining({
        scannerType: 'sca',
        state: { in: ['open', 'triaged', 'in_progress'] },
      }),
      data: expect.objectContaining({ state: 'resolved', slaNotifiedAt: null }),
    });
  });

  it('clears slaNotifiedAt when a resolved finding is reopened by ingest', async () => {
    const { findings, upserts, byFingerprint } = service();
    const batch = payload([raw()]);
    await findings.ingest(orgId, batch);
    const fp = upserts[0].create.fingerprint;
    byFingerprint.set(fp, { ...byFingerprint.get(fp), state: 'resolved' });
    await findings.ingest(orgId, batch);
    expect(upserts[1].update).toEqual(expect.objectContaining({ state: 'open', slaNotifiedAt: null }));
  });

  it('omits slaNotifiedAt from GET', async () => {
    const { findings, tx } = service();
    tx.finding.findUnique = vi.fn(async () => ({
      id: FINDING_A,
      slaNotifiedAt: new Date('2026-01-01T00:00:00.000Z'),
      events: [],
      asset: {},
    }));
    const got = await findings.get(orgId, FINDING_A);
    expect(got).not.toHaveProperty('slaNotifiedAt');
    expect(got).toEqual(expect.objectContaining({ id: FINDING_A }));
  });
});

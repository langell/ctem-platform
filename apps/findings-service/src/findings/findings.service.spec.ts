import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import type { FindingsReportedPayload, RawFinding } from '@ctem/contracts';
import { FindingNormalizer } from './finding-normalizer';
import { FindingsService } from './findings.service';

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
    create: { location: Record<string, unknown>; evidence: Record<string, unknown>; fingerprint: string };
    update: { location: Record<string, unknown>; evidence: Record<string, unknown> };
  }> = [];

  const tx = {
    finding: {
      findUnique: vi.fn(async () => null),
      upsert: vi.fn(async (args: (typeof upserts)[number]) => {
        upserts.push(args);
        return { id: randomUUID(), ...args.create };
      }),
      updateMany: vi.fn(async () => ({ count: 0 })),
    },
  };

  const prisma = {
    withOrg: vi.fn(async (_org: string, fn: (client: typeof tx) => Promise<unknown>) => fn(tx)),
  };

  const bus = { publish: vi.fn(async () => undefined) } as unknown as EventBus;
  const findings = new FindingsService(prisma as never, bus, new FindingNormalizer());
  return { findings, upserts, tx };
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

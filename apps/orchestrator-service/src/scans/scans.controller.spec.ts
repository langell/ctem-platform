import { BadRequestException, NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { CreateScanRequest } from '@ctem/contracts';
import { ZodBody } from '@ctem/service-kit';
import { ScansController } from './scans.controller';

const ORG_A = '4a6f9f4e-1111-4222-8333-444455556666';
const ORG_B = 'bbbbbbbb-2222-4333-8444-555566667777';
const SCAN_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ASSET_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
const FINDING_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2';

const matchingFinding = {
  id: FINDING_A,
  severity: 'high',
  riskScore: 80,
  kev: false,
  epssScore: 0.2,
  fixAvailable: true,
  scannerType: 'sca',
  asset: { kind: 'repository', exposure: 'internal', criticality: 'tier2', tags: {} },
};

function prismaForGet(opts: {
  scan?: object | null;
  findings?: object[];
  policies?: object[];
  exceptions?: object[];
} = {}) {
  const tx = {
    scan: {
      findUnique: vi.fn(async () => opts.scan ?? null),
    },
    finding: { findMany: vi.fn(async () => opts.findings ?? []) },
    policy: { findMany: vi.fn(async () => opts.policies ?? []) },
    riskException: { findMany: vi.fn(async () => opts.exceptions ?? []) },
  };
  const prisma = {
    withOrg: vi.fn(async (_orgId: string, fn: (client: typeof tx) => unknown) => fn(tx)),
  };
  return { prisma, tx };
}

describe('ScansController.get', () => {
  it('returns 404 when the scan is absent in the org (including RLS miss)', async () => {
    const { prisma, tx } = prismaForGet({ scan: null });
    const ctrl = new ScansController({} as never, prisma as never, {} as never);

    await expect(ctrl.get(ORG_B, SCAN_A)).rejects.toBeInstanceOf(NotFoundException);
    expect(prisma.withOrg).toHaveBeenCalledWith(ORG_B, expect.any(Function));
    expect(tx.scan.findUnique).toHaveBeenCalledWith({ where: { id: SCAN_A }, include: { jobs: true } });
  });

  it('returns the scan when it is visible in the JWT org', async () => {
    const scan = { id: SCAN_A, orgId: ORG_A, status: 'succeeded', scannerType: 'sca', jobs: [] };
    const { prisma } = prismaForGet({ scan });
    const ctrl = new ScansController({} as never, prisma as never, {} as never);

    await expect(ctrl.get(ORG_A, SCAN_A)).resolves.toEqual({ ...scan, conclusion: 'passed' });
  });

  it('returns conclusion failed when a matching fail_build rule wins', async () => {
    const scan = {
      id: SCAN_A,
      orgId: ORG_A,
      status: 'succeeded',
      scannerType: 'sca',
      jobs: [{ assetId: ASSET_A, findingCount: 1 }],
    };
    const { prisma } = prismaForGet({
      scan,
      findings: [matchingFinding],
      policies: [
        {
          enabled: true,
          priority: 10,
          condition: { severityAtLeast: 'high' },
          actions: ['fail_build'],
        },
      ],
    });
    const ctrl = new ScansController({} as never, prisma as never, {} as never);

    await expect(ctrl.get(ORG_A, SCAN_A)).resolves.toMatchObject({
      id: SCAN_A,
      conclusion: 'failed',
    });
  });

  it('does not fail conclusion from a client-supplied field — only a matching fail_build rule', async () => {
    const scan = {
      id: SCAN_A,
      orgId: ORG_A,
      status: 'succeeded',
      scannerType: 'sca',
      conclusion: 'failed',
      jobs: [{ assetId: ASSET_A, findingCount: 1 }],
    };
    const { prisma } = prismaForGet({
      scan,
      findings: [matchingFinding],
      policies: [{ enabled: true, priority: 10, condition: { kevOnly: true }, actions: ['notify'] }],
    });
    const ctrl = new ScansController({} as never, prisma as never, {} as never);

    await expect(ctrl.get(ORG_A, SCAN_A)).resolves.toMatchObject({ conclusion: 'passed' });
  });
});

describe('ScansController.create refuses a client conclusion', () => {
  it('ZodBody 400s a POST that tries to set conclusion', () => {
    const pipe = new ZodBody(CreateScanRequest);
    expect(() => pipe.transform({ scannerType: 'sca', conclusion: 'failed' })).toThrow(
      BadRequestException,
    );
    expect(() =>
      pipe.transform({ scannerType: 'sca', options: { conclusion: 'failed' } }),
    ).toThrow(BadRequestException);
    expect(pipe.transform({ scannerType: 'sca' })).toMatchObject({ scannerType: 'sca' });
  });
});

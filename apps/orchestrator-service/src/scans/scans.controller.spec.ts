import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { ScansController } from './scans.controller';

const ORG_A = '4a6f9f4e-1111-4222-8333-444455556666';
const ORG_B = 'bbbbbbbb-2222-4333-8444-555566667777';
const SCAN_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

describe('ScansController.get', () => {
  it('returns 404 when the scan is absent in the org (including RLS miss)', async () => {
    const findUnique = vi.fn(async () => null);
    const prisma = {
      withOrg: vi.fn(async (_orgId: string, fn: (tx: unknown) => unknown) =>
        fn({ scan: { findUnique } }),
      ),
    };
    const ctrl = new ScansController({} as never, prisma as never, {} as never);

    await expect(ctrl.get(ORG_B, SCAN_A)).rejects.toBeInstanceOf(NotFoundException);
    expect(prisma.withOrg).toHaveBeenCalledWith(ORG_B, expect.any(Function));
    expect(findUnique).toHaveBeenCalledWith({ where: { id: SCAN_A }, include: { jobs: true } });
  });

  it('returns the scan when it is visible in the JWT org', async () => {
    const scan = { id: SCAN_A, orgId: ORG_A, jobs: [] };
    const prisma = {
      withOrg: vi.fn(async (_orgId: string, fn: (tx: unknown) => unknown) =>
        fn({ scan: { findUnique: vi.fn(async () => scan) } }),
      ),
    };
    const ctrl = new ScansController({} as never, prisma as never, {} as never);

    await expect(ctrl.get(ORG_A, SCAN_A)).resolves.toEqual(scan);
  });
});

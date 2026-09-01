import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { AssetsService } from './assets.service';

const ORG_A = '4a6f9f4e-1111-4222-8333-444455556666';
const ORG_B = 'bbbbbbbb-2222-4333-8444-555566667777';
const ASSET_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

describe('AssetsService.get', () => {
  it('returns 404 when the asset is absent in the org (including RLS miss)', async () => {
    const findUnique = vi.fn(async () => null);
    const prisma = {
      withOrg: vi.fn(async (_orgId: string, fn: (tx: unknown) => unknown) =>
        fn({ asset: { findUnique } }),
      ),
    };
    const assets = new AssetsService(prisma as never, { publish: vi.fn() } as never);

    await expect(assets.get(ORG_B, ASSET_A)).rejects.toBeInstanceOf(NotFoundException);
    expect(prisma.withOrg).toHaveBeenCalledWith(ORG_B, expect.any(Function));
    expect(findUnique).toHaveBeenCalledWith({ where: { id: ASSET_A } });
  });
});

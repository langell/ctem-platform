import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { AssetGraphService } from './asset-graph.service';

const ORG_B = 'bbbbbbbb-2222-4333-8444-555566667777';
const ASSET_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

describe('AssetGraphService.neighborhood', () => {
  it('returns 404 when the asset is absent in the org (including RLS miss)', async () => {
    const findUnique = vi.fn(async () => null);
    const queryRawUnsafe = vi.fn();
    const prisma = {
      withOrg: vi.fn(async (_orgId: string, fn: (tx: unknown) => unknown) =>
        fn({ asset: { findUnique }, $queryRawUnsafe: queryRawUnsafe }),
      ),
    };
    const graph = new AssetGraphService(prisma as never);

    await expect(graph.neighborhood(ORG_B, ASSET_A)).rejects.toBeInstanceOf(NotFoundException);
    expect(prisma.withOrg).toHaveBeenCalledWith(ORG_B, expect.any(Function));
    expect(findUnique).toHaveBeenCalledWith({ where: { id: ASSET_A }, select: { id: true } });
    expect(queryRawUnsafe).not.toHaveBeenCalled();
  });
});

import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { RiskScoringService } from './risk-scoring.service';

describe('RiskScoringService', () => {
  it('returns 404 when the finding is absent in the org (including RLS miss)', async () => {
    const prisma = {
      withOrg: vi.fn(async (_orgId: string, fn: (tx: unknown) => unknown) =>
        fn({ finding: { findUnique: vi.fn(async () => null) } }),
      ),
    };
    const scoring = new RiskScoringService(prisma as never);
    await expect(
      scoring.score('bbbbbbbb-2222-4333-8444-555566667777', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
    ).rejects.toBeInstanceOf(NotFoundException);
    expect(prisma.withOrg).toHaveBeenCalledWith(
      'bbbbbbbb-2222-4333-8444-555566667777',
      expect.any(Function),
    );
  });
});

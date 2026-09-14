import { NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { RiskScoringService } from './risk-scoring.service';

const ORG = 'bbbbbbbb-2222-4333-8444-555566667777';
const FINDING = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

function scoringFor(over: Record<string, unknown> = {}) {
  const finding = {
    id: FINDING,
    severity: 'high',
    cvssScore: 7.5,
    epssScore: 0.2,
    kev: false,
    validation: 'not_validated',
    asset: { exposure: 'internal', criticality: 'tier2' },
    ...over,
  };
  const update = vi.fn(async () => finding);
  const prisma = {
    withOrg: vi.fn(async (_orgId: string, fn: (tx: unknown) => unknown) =>
      fn({
        finding: {
          findUnique: vi.fn(async () => finding),
          update,
        },
      }),
    ),
  };
  return { scoring: new RiskScoringService(prisma as never), update, finding };
}

describe('RiskScoringService', () => {
  it('returns 404 when the finding is absent in the org (including RLS miss)', async () => {
    const prisma = {
      withOrg: vi.fn(async (_orgId: string, fn: (tx: unknown) => unknown) =>
        fn({ finding: { findUnique: vi.fn(async () => null) } }),
      ),
    };
    const scoring = new RiskScoringService(prisma as never);
    await expect(scoring.score(ORG, FINDING)).rejects.toBeInstanceOf(NotFoundException);
    expect(prisma.withOrg).toHaveBeenCalledWith(ORG, expect.any(Function));
  });

  it('applies the validation multiplier so exploitable outranks not_validated', async () => {
    // high=0.8, epss=0.2, internal=0.5, tier2=0.5 → base 0.515
    const base = 0.3 * 0.8 + 0.25 * 0.2 + 0.25 * 0.5 + 0.2 * 0.5;
    const { scoring: unset } = scoringFor({ validation: 'not_validated' });
    const { scoring: reachable } = scoringFor({ validation: 'reachable' });
    const { scoring: exploitable } = scoringFor({ validation: 'exploitable' });
    const { scoring: notReachable } = scoringFor({ validation: 'not_reachable' });

    expect((await unset.score(ORG, FINDING)).score).toBe(Math.round(base * 100));
    expect((await reachable.score(ORG, FINDING)).score).toBe(Math.round(base * 1.1 * 100));
    expect((await exploitable.score(ORG, FINDING)).score).toBe(Math.round(base * 1.25 * 100));
    expect((await notReachable.score(ORG, FINDING)).score).toBe(Math.round(base * 0.4 * 100));
    expect((await exploitable.score(ORG, FINDING)).score).toBeGreaterThan(
      (await unset.score(ORG, FINDING)).score,
    );
  });
});

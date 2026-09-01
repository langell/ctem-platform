import { describe, expect, it, vi } from 'vitest';
import { SUBJECTS } from '@ctem/contracts';
import { PolicyEngineService } from './policy-engine.service';
import { SEED_KEV_OR_CRITICAL_POLICY_ID } from './seed-notify';

const orgId = '11111111-1111-4111-8111-111111111111';
const findingId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

function finding(over: Record<string, unknown> = {}) {
  return {
    id: findingId,
    severity: 'medium',
    riskScore: 40,
    kev: false,
    epssScore: 0.1,
    fixAvailable: false,
    scannerType: 'sca',
    asset: { kind: 'repository', exposure: 'internal', criticality: 'tier2', tags: {} },
    ...over,
  };
}

function engine(row: ReturnType<typeof finding>, policies: object[] = []) {
  const published: Array<{ subject: string; orgId: string; payload: unknown }> = [];
  const tx = {
    finding: {
      findUniqueOrThrow: vi.fn(async () => row),
      update: vi.fn(),
    },
    policy: { findMany: vi.fn(async () => policies) },
    riskException: { count: vi.fn(async () => 0) },
  };
  const prisma = {
    withOrg: vi.fn(async (_org: string, fn: (t: typeof tx) => unknown) => fn(tx)),
  };
  const bus = {
    publish: vi.fn(async (subject: string, oid: string, payload: unknown) => {
      published.push({ subject, orgId: oid, payload });
    }),
  };
  return {
    service: new PolicyEngineService(prisma as never, bus as never),
    published,
    bus,
  };
}

describe('PolicyEngineService seed KEV-or-critical rule', () => {
  it('emits policy.violated notify for a KEV finding when no org policy matches', async () => {
    const { service, published } = engine(finding({ kev: true, severity: 'medium' }));
    await expect(service.evaluate(orgId, findingId)).resolves.toEqual(['notify']);
    expect(published).toEqual([
      {
        subject: SUBJECTS.policyViolated,
        orgId,
        payload: {
          findingId,
          policyId: SEED_KEV_OR_CRITICAL_POLICY_ID,
          actions: ['notify'],
        },
      },
    ]);
  });

  it('emits policy.violated notify for a critical finding when no org policy matches', async () => {
    const { service, published } = engine(finding({ kev: false, severity: 'critical' }));
    await expect(service.evaluate(orgId, findingId)).resolves.toEqual(['notify']);
    expect(published[0]?.payload).toMatchObject({
      policyId: SEED_KEV_OR_CRITICAL_POLICY_ID,
      actions: ['notify'],
    });
  });

  it('does not emit the seed rule for a non-KEV high finding', async () => {
    const { service, published } = engine(finding({ kev: false, severity: 'high' }));
    await expect(service.evaluate(orgId, findingId)).resolves.toEqual([]);
    expect(published).toEqual([]);
  });

  it('lets a matching tenant policy win so the seed does not double-notify', async () => {
    const { service, published } = engine(finding({ kev: true, severity: 'critical' }), [
      {
        id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        condition: { kevOnly: true },
        actions: ['notify', 'ticket'],
        slaHours: null,
      },
    ]);
    await expect(service.evaluate(orgId, findingId)).resolves.toEqual(['notify', 'ticket']);
    expect(published).toHaveLength(1);
    expect(published[0]?.payload).toMatchObject({
      policyId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      actions: ['notify', 'ticket'],
    });
  });
});

import { BadRequestException, NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { PolicyService } from './policy.service';

const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const POLICY_A = '11111111-1111-4111-8111-111111111111';

function service(opts: {
  existing?: object | null;
  created?: object;
  updated?: object;
  listed?: object[];
} = {}) {
  const created = opts.created ?? { id: POLICY_A, orgId: ORG_A, priority: 10 };
  const updated = opts.updated ?? { id: POLICY_A, orgId: ORG_A, priority: 5 };
  const tx = {
    policy: {
      findMany: vi.fn(async () => opts.listed ?? []),
      findUnique: vi.fn(async () => opts.existing ?? null),
      create: vi.fn(async (args: { data: object }) => ({ ...created, ...args.data })),
      update: vi.fn(async (args: { data: object }) => ({ ...updated, ...args.data })),
    },
  };
  const prisma = {
    withOrg: vi.fn(async (_orgId: string, fn: (t: typeof tx) => unknown) => fn(tx)),
  };
  return { policies: new PolicyService(prisma as never), prisma, tx };
}

const notifyRule = {
  name: 'KEV notify',
  description: '',
  enabled: true,
  priority: 10,
  condition: { kevOnly: true },
  actions: ['notify'] as const,
  slaHours: null,
};

describe('PolicyService.get', () => {
  it('returns 404 when the policy is absent in the org (including RLS miss)', async () => {
    const { policies, prisma, tx } = service({ existing: null });
    await expect(policies.get(ORG_B, POLICY_A)).rejects.toBeInstanceOf(NotFoundException);
    expect(prisma.withOrg).toHaveBeenCalledWith(ORG_B, expect.any(Function));
    expect(tx.policy.findUnique).toHaveBeenCalledWith({ where: { id: POLICY_A } });
  });

  it('does not return an empty 200 stand-in for an org miss', async () => {
    const { policies } = service({ existing: null });
    await expect(policies.get(ORG_B, POLICY_A)).rejects.toBeInstanceOf(NotFoundException);
    await expect(policies.get(ORG_B, POLICY_A)).rejects.not.toEqual(null);
    await expect(policies.get(ORG_B, POLICY_A)).rejects.not.toEqual([]);
  });
});

describe('PolicyService.create / update', () => {
  it('persists create order via priority', async () => {
    const { policies, prisma, tx } = service();
    await policies.create(ORG_A, { ...notifyRule, name: 'first', priority: 20 });
    expect(prisma.withOrg).toHaveBeenCalledWith(ORG_A, expect.any(Function));
    expect(tx.policy.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        orgId: ORG_A,
        name: 'first',
        priority: 20,
        actions: ['notify'],
      }),
    });
  });

  it('persists an updated priority so list order can change', async () => {
    const { policies, tx } = service({
      existing: { id: POLICY_A, orgId: ORG_A, priority: 10, actions: ['notify'] },
    });
    await policies.update(ORG_A, POLICY_A, { priority: 50 });
    expect(tx.policy.findUnique).toHaveBeenCalledWith({ where: { id: POLICY_A } });
    expect(tx.policy.update).toHaveBeenCalledWith({
      where: { id: POLICY_A },
      data: expect.objectContaining({ priority: 50 }),
    });
  });

  it('returns 404 when org B updates an org A rule (including RLS miss)', async () => {
    const { policies, prisma } = service({ existing: null });
    await expect(policies.update(ORG_B, POLICY_A, { priority: 1 })).rejects.toBeInstanceOf(
      NotFoundException,
    );
    expect(prisma.withOrg).toHaveBeenCalledWith(ORG_B, expect.any(Function));
  });

  it('persists a ticket action from the editor', async () => {
    const { policies, tx } = service();
    await policies.create(ORG_A, { ...notifyRule, name: 'KEV ticket', actions: ['ticket'] });
    expect(tx.policy.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        orgId: ORG_A,
        name: 'KEV ticket',
        actions: ['ticket'],
      }),
    });
  });

  it('refuses fail_build / block_deploy on create and update', async () => {
    const { policies } = service({
      existing: { id: POLICY_A, orgId: ORG_A, actions: ['notify'] },
    });
    await expect(
      policies.create(ORG_A, { ...notifyRule, actions: ['fail_build'] }),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      policies.create(ORG_A, { ...notifyRule, actions: ['notify', 'fail_build'] }),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      policies.update(ORG_A, POLICY_A, { actions: ['block_deploy'] }),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      policies.update(ORG_A, POLICY_A, { actions: ['ticket', 'fail_build'] }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('refuses a tenant webhook URL if it appears on create or update', async () => {
    const { policies, tx } = service({
      existing: { id: POLICY_A, orgId: ORG_A, actions: ['notify'] },
    });
    await expect(
      policies.create(ORG_A, {
        ...notifyRule,
        webhookUrl: 'https://attacker.test/hooks/tenant',
      }),
    ).rejects.toMatchObject({
      message: expect.stringMatching(/tenant webhook URL/i),
    });
    await expect(
      policies.create(ORG_A, {
        ...notifyRule,
        condition: { kevOnly: true, webhookUrl: 'https://attacker.test/x' },
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      policies.update(ORG_A, POLICY_A, { hookUrl: 'https://hooks.example/tenant' }),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      policies.create(ORG_A, {
        ...notifyRule,
        actions: ['ticket'],
        jiraUrl: 'https://evil.example/jira',
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(tx.policy.create).not.toHaveBeenCalled();
    expect(tx.policy.update).not.toHaveBeenCalled();
  });
});

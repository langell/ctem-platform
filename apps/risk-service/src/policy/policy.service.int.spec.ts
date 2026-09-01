import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, createPolicy, deleteOrgCascade, ownerClient } from '@ctem/testing';
import { PolicyService } from './policy.service';

/**
 * Policy editor writes against real Postgres as `ctem_app`. Order is the
 * persisted priority; org B must not read or update org A rules (404).
 */
describe('PolicyService (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let service: PolicyService;
  let orgA: string;
  let orgB: string;

  beforeAll(async () => {
    owner = ownerClient();
    orgA = (await createOrg(owner)).id;
    orgB = (await createOrg(owner)).id;
    prisma = new PrismaService();
    service = new PolicyService(prisma);
  });

  afterAll(async () => {
    await deleteOrgCascade(owner, orgA);
    await deleteOrgCascade(owner, orgB);
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('create/update persist list order by priority', async () => {
    const later = await service.create(orgA, {
      name: 'later-rule',
      description: '',
      enabled: true,
      priority: 20,
      condition: { kevOnly: true },
      actions: ['notify'],
      slaHours: null,
    });
    const first = await service.create(orgA, {
      name: 'first-rule',
      description: '',
      enabled: true,
      priority: 10,
      condition: { severityAtLeast: 'critical' },
      actions: ['notify'],
      slaHours: null,
    });

    const listed = await service.list(orgA);
    expect(listed.map((p) => p.id)).toEqual([first.id, later.id]);
    expect(listed.map((p) => p.priority)).toEqual([10, 20]);

    await service.update(orgA, first.id, { priority: 30 });
    const relisted = await service.list(orgA);
    expect(relisted.map((p) => p.id)).toEqual([later.id, first.id]);
    expect(relisted.map((p) => p.priority)).toEqual([20, 30]);
  });

  it('org B cannot read or update an org A rule (404, not 500 or empty 200)', async () => {
    const planted = await createPolicy(owner, orgA, {
      name: 'org-a-only',
      priority: 3,
      actions: ['notify'],
    });

    await expect(service.get(orgB, planted.id)).rejects.toBeInstanceOf(NotFoundException);
    await expect(service.update(orgB, planted.id, { name: 'stolen' })).rejects.toBeInstanceOf(
      NotFoundException,
    );

    const still = await service.get(orgA, planted.id);
    expect(still.name).toBe('org-a-only');
    expect(still.id).toBe(planted.id);
  });
});

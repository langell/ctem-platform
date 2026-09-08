import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { ROLE_PERMISSIONS, UserId, type Principal, type Role } from '@ctem/contracts';
import {
  createOrg,
  createUserWithMembership,
  deleteOrgCascade,
  DEMO_IDP_SUBJECT,
  DEMO_ORG_ID,
  DEMO_USER_EMAIL,
  ownerClient,
  seedDemoOrg,
  uniqueSlug,
} from '@ctem/testing';
import { OrgService } from './org.service';

function actor(orgId: string, userId: string, role: Role): Principal {
  return {
    userId,
    orgId,
    role,
    permissions: ROLE_PERMISSIONS[role],
    serviceAccount: null,
    traceId: 'org-service-int',
  };
}

describe('OrgService members + JWT resolve (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let service: OrgService;
  let orgId: string;
  let orgBId: string;
  const userIds: string[] = [];

  beforeAll(async () => {
    owner = ownerClient();
    orgId = (await createOrg(owner)).id;
    orgBId = (await createOrg(owner)).id;
    prisma = new PrismaService();
    service = new OrgService(prisma);
  });

  afterAll(async () => {
    await deleteOrgCascade(owner, orgId, userIds);
    await deleteOrgCascade(owner, orgBId);
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  async function member(role: Role, overrides: { email?: string; idpSubject?: string } = {}) {
    const user = await createUserWithMembership(owner, orgId, role, overrides);
    userIds.push(user.id);
    return user;
  }

  it('resolves Membership role and a UUID users.id, never the IdP sub', async () => {
    const sub = `idp|${uniqueSlug('analyst')}`;
    const user = await member('security_analyst', {
      email: `${uniqueSlug('analyst')}@test.local`,
      idpSubject: sub,
    });

    const resolved = await service.resolveJwt({
      sub,
      orgId,
      email: user.email,
      name: 'Renamed Analyst',
    });
    expect(resolved.userId).toBe(user.id);
    expect(resolved.userId).not.toBe(sub);
    expect(UserId.safeParse(resolved.userId).success).toBe(true);
    expect(resolved.role).toBe('security_analyst');
    expect(resolved.orgId).toBe(orgId);

    const updated = await owner.user.findUnique({ where: { id: user.id } });
    expect(updated?.name).toBe('Renamed Analyst');
    expect(updated?.idpSubject).toBe(sub);
  });

  it('JIT upserts User by idpSubject then 403s when Membership is missing', async () => {
    const sub = `idp|${uniqueSlug('stranger')}`;
    const email = `${uniqueSlug('stranger')}@test.local`;
    await expect(service.resolveJwt({ sub, orgId, email, name: 'Stranger' })).rejects.toBeInstanceOf(
      ForbiddenException,
    );

    const created = await owner.user.findUnique({ where: { idpSubject: sub } });
    expect(created).not.toBeNull();
    expect(created!.id).not.toBe(sub);
    expect(UserId.safeParse(created!.id).success).toBe(true);
    expect(created!.email).toBe(email);
    userIds.push(created!.id);

    const membership = await owner.membership.findUnique({
      where: { orgId_userId: { orgId, userId: created!.id } },
    });
    expect(membership).toBeNull();
  });

  it('accepts a CTEM invite on first login (email match) and mints Membership', async () => {
    const ownerUser = await member('owner');
    const email = `${uniqueSlug('invited')}@test.local`;
    const invited = await service.invite(orgId, actor(orgId, ownerUser.id, 'owner'), {
      email,
      role: 'developer',
    });
    expect(invited.token).toMatch(/^ctem_inv_/);
    expect(invited.role).toBe('developer');

    const sub = `idp|${uniqueSlug('invited')}`;
    const resolved = await service.resolveJwt({
      sub,
      orgId,
      email,
      name: 'Invited Dev',
    });
    expect(resolved.role).toBe('developer');
    expect(resolved.userId).not.toBe(sub);
    userIds.push(resolved.userId);

    const membership = await owner.membership.findUnique({
      where: { orgId_userId: { orgId, userId: resolved.userId } },
    });
    expect(membership?.role).toBe('developer');
    expect(membership?.disabledAt).toBeNull();
  });

  it('demo seed Membership lets the Keycloak analyst resolve after JWT roles are ignored', async () => {
    await seedDemoOrg(owner);
    const resolved = await service.resolveJwt({
      sub: DEMO_IDP_SUBJECT,
      orgId: DEMO_ORG_ID,
      email: DEMO_USER_EMAIL,
      name: 'Demo Analyst',
    });
    expect(resolved.orgId).toBe(DEMO_ORG_ID);
    expect(resolved.role).toBe('owner');
    expect(resolved.userId).not.toBe(DEMO_IDP_SUBJECT);
    expect(UserId.safeParse(resolved.userId).success).toBe(true);

    const user = await owner.user.findUnique({ where: { id: resolved.userId } });
    expect(user?.idpSubject).toBe(DEMO_IDP_SUBJECT);
    expect(user?.email).toBe(DEMO_USER_EMAIL);
  });

  it('refuses a non-owner granting or revoking owner', async () => {
    const admin = await member('admin');
    const developer = await member('developer');
    const ownerUser = await member('owner');
    await expect(
      service.setRole(orgId, actor(orgId, admin.id, 'admin'), developer.id, 'owner'),
    ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(
      service.setRole(orgId, actor(orgId, admin.id, 'admin'), ownerUser.id, 'admin'),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('protects the last owner from demote and disable', async () => {
    const isolated = (await createOrg(owner)).id;
    const only = await createUserWithMembership(owner, isolated, 'owner');
    const extraIds = [only.id];
    try {
      await expect(
        service.setRole(isolated, actor(isolated, only.id, 'owner'), only.id, 'admin'),
      ).rejects.toThrow(/last owner/);
      await expect(
        service.disable(isolated, actor(isolated, only.id, 'owner'), only.id),
      ).rejects.toThrow(/last owner/);

      const second = await createUserWithMembership(owner, isolated, 'owner');
      extraIds.push(second.id);
      const demoted = await service.setRole(
        isolated,
        actor(isolated, second.id, 'owner'),
        only.id,
        'admin',
      );
      expect(demoted.role).toBe('admin');
    } finally {
      await deleteOrgCascade(owner, isolated, extraIds);
    }
  });

  it('returns 404 for a member that is not in this org (cross-org miss)', async () => {
    const here = await member('developer');
    const elsewhere = await createUserWithMembership(owner, orgBId, 'developer');
    userIds.push(elsewhere.id);

    const ownerUser = await member('owner');
    await expect(
      service.setRole(orgId, actor(orgId, ownerUser.id, 'owner'), elsewhere.id, 'admin'),
    ).rejects.toBeInstanceOf(NotFoundException);
    await expect(
      service.disable(orgId, actor(orgId, ownerUser.id, 'owner'), elsewhere.id),
    ).rejects.toBeInstanceOf(NotFoundException);
    await expect(
      service.setRole(orgBId, actor(orgBId, elsewhere.id, 'developer'), here.id, 'admin'),
    ).rejects.toBeInstanceOf(NotFoundException);
  });

  it('rejects invalid user ids with 4xx, never a Prisma 500', async () => {
    const ownerUser = await member('owner');
    await expect(
      service.setRole(orgId, actor(orgId, ownerUser.id, 'owner'), 'idp|alice', 'admin'),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      service.disable(orgId, actor(orgId, ownerUser.id, 'owner'), 'not-a-uuid'),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      service.setRole(
        orgId,
        actor(orgId, ownerUser.id, 'owner'),
        '00000000-0000-4000-8000-000000000099',
        'admin',
      ),
    ).rejects.toBeInstanceOf(NotFoundException);
  });

  it('soft-disables Membership so the next resolve is 403 and keeps the User', async () => {
    const ownerUser = await member('owner');
    const target = await member('developer', { idpSubject: `idp|${uniqueSlug('disable')}` });
    await service.disable(orgId, actor(orgId, ownerUser.id, 'owner'), target.id);

    await expect(
      service.resolveJwt({
        sub: target.idpSubject,
        orgId,
        email: target.email,
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);

    expect(await owner.user.findUnique({ where: { id: target.id } })).not.toBeNull();
    const row = await owner.membership.findUnique({
      where: { orgId_userId: { orgId, userId: target.id } },
    });
    expect(row?.disabledAt).not.toBeNull();
  });

  it('conflicts when inviting an email that already has an active membership', async () => {
    const ownerUser = await member('owner');
    const existing = await member('developer');
    await expect(
      service.invite(orgId, actor(orgId, ownerUser.id, 'owner'), {
        email: existing.email,
        role: 'auditor',
      }),
    ).rejects.toBeInstanceOf(ConflictException);
  });
});

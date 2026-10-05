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
  appClient,
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
    await service.onModuleDestroy();
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
    await expect(
      service.resolveJwt({ sub, orgId, email, name: 'Stranger' }),
    ).rejects.toBeInstanceOf(ForbiddenException);

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

  it('creates one org for a subject with no membership and then resolves that org', async () => {
    const sub = `idp|${uniqueSlug('signup')}`;
    const email = `${uniqueSlug('signup')}@test.local`;
    const resolved = await service.resolveActiveMemberships({ sub, email, name: 'New Owner' });
    expect(resolved.memberships).toEqual([]);
    expect(resolved.userId).not.toBe(sub);
    userIds.push(resolved.userId);

    const app = appClient();
    try {
      expect(await app.membership.count({ where: { userId: resolved.userId } })).toBe(0);
    } finally {
      await app.$disconnect();
    }

    const slug = uniqueSlug('signup');
    const org = await service.createOrgForSubject(sub, '  Signup Org  ', slug);
    expect(org.plan).toBe('trial');
    expect(org.name).toBe('Signup Org');
    expect(org.slug).toBe(slug);

    const again = await service.resolveActiveMemberships({ sub, email });
    expect(again.userId).toBe(resolved.userId);
    expect(again.memberships).toEqual([{ orgId: org.id, role: 'owner' }]);

    const membership = await owner.membership.findUnique({
      where: { orgId_userId: { orgId: org.id, userId: resolved.userId } },
    });
    expect(membership?.role).toBe('owner');
    expect(membership?.disabledAt).toBeNull();
    const policies = await owner.policy.findMany({ where: { orgId: org.id } });
    expect(policies).toHaveLength(3);

    await expect(
      service.createOrgForSubject(sub, 'Second', uniqueSlug('second')),
    ).rejects.toBeInstanceOf(ConflictException);
    await deleteOrgCascade(owner, org.id);
  });

  it('does not return another user membership and ignores disabled rows', async () => {
    const sub = `idp|${uniqueSlug('solo')}`;
    const email = `${uniqueSlug('solo')}@test.local`;
    const mine = await service.resolveActiveMemberships({ sub, email, name: 'Solo' });
    userIds.push(mine.userId);
    const slug = uniqueSlug('solo');
    const org = await service.createOrgForSubject(sub, 'Solo', slug);

    const other = await createUserWithMembership(owner, orgBId, 'owner', {
      email: `${uniqueSlug('other')}@test.local`,
      idpSubject: `idp|${uniqueSlug('other')}`,
    });
    userIds.push(other.id);

    const visible = await service.resolveActiveMemberships({ sub, email });
    expect(visible.memberships.map((m) => m.orgId)).toEqual([org.id]);
    expect(visible.memberships.some((m) => m.orgId === orgBId)).toBe(false);

    await owner.membership.update({
      where: { orgId_userId: { orgId: org.id, userId: mine.userId } },
      data: { disabledAt: new Date() },
    });
    const afterDisable = await service.resolveActiveMemberships({ sub, email });
    expect(afterDisable.memberships).toEqual([]);

    const replacement = await service.createOrgForSubject(sub, 'Replacement', uniqueSlug('repl'));
    expect(replacement.id).not.toBe(org.id);
    await deleteOrgCascade(owner, org.id);
    await deleteOrgCascade(owner, replacement.id);
  });

  it('rejects an invalid org payload and a taken slug without a 500', async () => {
    const sub = `idp|${uniqueSlug('invalid')}`;
    const email = `${uniqueSlug('invalid')}@test.local`;
    const user = await service.resolveActiveMemberships({ sub, email, name: 'Invalid' });
    userIds.push(user.userId);

    await expect(service.createOrgForSubject(sub, ' ', 'abc')).rejects.toBeInstanceOf(
      BadRequestException,
    );
    await expect(service.createOrgForSubject(sub, 'Ok', 'ab')).rejects.toBeInstanceOf(
      BadRequestException,
    );
    await expect(service.createOrgForSubject(sub, 'Ok', 'NOPE')).rejects.toBeInstanceOf(
      BadRequestException,
    );

    const slug = uniqueSlug('taken');
    const org = await service.createOrgForSubject(sub, 'Taken', slug);
    const otherSub = `idp|${uniqueSlug('taken2')}`;
    const other = await service.resolveActiveMemberships({
      sub: otherSub,
      email: `${uniqueSlug('taken2')}@test.local`,
      name: 'Other',
    });
    userIds.push(other.userId);
    await expect(service.createOrgForSubject(otherSub, 'Taken 2', slug)).rejects.toBeInstanceOf(
      ConflictException,
    );
    await deleteOrgCascade(owner, org.id);
  });

  it('resolves the demo analyst membership when the token has no separate org lookup key', async () => {
    await seedDemoOrg(owner);
    const resolved = await service.resolveActiveMemberships({
      sub: DEMO_IDP_SUBJECT,
      email: DEMO_USER_EMAIL,
      name: 'Demo Analyst',
    });
    expect(resolved.memberships).toEqual([{ orgId: DEMO_ORG_ID, role: 'owner' }]);
    expect(resolved.userId).not.toBe(DEMO_IDP_SUBJECT);
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

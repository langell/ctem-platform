import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import { PrismaService, type PrismaTransaction } from '@ctem/db';
import {
  InviteMemberRequest,
  ResolveJwtRequest,
  Role,
  UserId,
  type Principal,
} from '@ctem/contracts';

const INVITE_TTL_MS = 14 * 24 * 60 * 60 * 1000;
const INVITE_PREFIX = 'ctem_inv_';

/**
 * Tenant identity: Membership is the AuthZ source of truth. Keycloak authenticates;
 * realm roles never mint a Membership. The only add path is a CTEM-side invite that
 * becomes a Membership on first login when `claims.email` matches a pending invite.
 */
@Injectable()
export class OrgService {
  constructor(private readonly prisma: PrismaService) {}

  /** Org creation is the one legitimately cross-tenant write in the system. */
  async createOrg(name: string, slug: string, ownerUserId: string) {
    return this.prisma.unsafeCrossTenant('org bootstrap has no tenant context yet', async (db) =>
      db.organization.create({
        data: {
          name,
          slug,
          memberships: { create: { userId: ownerUserId, role: 'owner' } },
          policies: {
            // Sensible defaults so a new org is not staring at an empty policy list.
            create: [
              {
                name: 'Internet-facing critical',
                description: 'Anything critical and reachable from the internet is a page.',
                priority: 10,
                condition: { severityAtLeast: 'critical', exposure: ['internet_facing'] },
                actions: ['notify', 'ticket', 'block_deploy'],
                slaHours: 24,
              },
              {
                name: 'Known exploited vulnerabilities',
                description: 'On the CISA KEV list — fix within a week regardless of CVSS.',
                priority: 20,
                condition: { kevOnly: true },
                actions: ['notify', 'ticket'],
                slaHours: 168,
              },
              {
                name: 'High severity with a fix',
                description: 'Fail the build only when the team can actually act.',
                priority: 50,
                condition: { severityAtLeast: 'high', requireFixAvailable: true },
                actions: ['ticket', 'fail_build'],
                slaHours: 336,
              },
            ],
          },
        },
      }),
    );
  }

  async members(orgId: string) {
    return this.prisma.withOrg(orgId, async (tx) => {
      const rows = await tx.membership.findMany({
        include: { user: true },
        orderBy: { createdAt: 'asc' },
      });
      return rows.map((m) => ({
        userId: m.userId,
        email: m.user.email,
        name: m.user.name,
        role: m.role,
        disabledAt: m.disabledAt,
        createdAt: m.createdAt,
      }));
    });
  }

  async setRole(orgId: string, actor: Principal, userId: string, role: Role) {
    this.requireUserId(userId);
    return this.prisma.withOrg(orgId, async (tx) => {
      const membership = await this.requireMembership(tx, orgId, userId);
      this.assertOwnerRoleChange(actor.role, membership.role, role);
      if (membership.role === 'owner' && role !== 'owner') {
        await this.assertNotLastActiveOwner(tx, orgId);
      }
      return tx.membership.update({
        where: { orgId_userId: { orgId, userId } },
        data: { role },
      });
    });
  }

  /**
   * One add path: persist a pending invite. Membership is created on first
   * login (email match), not by Keycloak realm roles and not by Admin API.
   */
  async invite(orgId: string, actor: Principal, input: InviteMemberRequest) {
    const invitedBy = UserId.safeParse(actor.userId);
    if (!invitedBy.success) {
      throw new BadRequestException('Only a human member can invite');
    }
    if (input.role === 'owner' && actor.role !== 'owner') {
      throw new ForbiddenException('Only an owner can grant ownership');
    }
    const email = input.email.trim().toLowerCase();
    const token = `${INVITE_PREFIX}${randomBytes(32).toString('base64url')}`;
    const expiresAt = new Date(Date.now() + INVITE_TTL_MS);

    return this.prisma.withOrg(orgId, async (tx) => {
      const existingUser = await tx.user.findUnique({ where: { email } });
      if (existingUser) {
        const existing = await tx.membership.findUnique({
          where: { orgId_userId: { orgId, userId: existingUser.id } },
        });
        if (existing && !existing.disabledAt) {
          throw new ConflictException('User is already a member of this organization');
        }
      }

      const pending = await tx.membershipInvite.findFirst({
        where: { orgId, email, acceptedAt: null },
        orderBy: { createdAt: 'desc' },
      });
      const data = {
        email,
        role: input.role,
        tokenHash: this.hash(token),
        invitedBy: invitedBy.data,
        expiresAt,
        acceptedAt: null,
      };
      if (pending) {
        await tx.membershipInvite.update({ where: { id: pending.id }, data });
      } else {
        await tx.membershipInvite.create({ data: { orgId, ...data } });
      }
      return { email, role: input.role, expiresAt, token };
    });
  }

  async disable(orgId: string, actor: Principal, userId: string) {
    this.requireUserId(userId);
    return this.prisma.withOrg(orgId, async (tx) => {
      const membership = await this.requireMembership(tx, orgId, userId);
      if (membership.disabledAt) {
        return membership;
      }
      if (membership.role === 'owner') {
        if (actor.role !== 'owner') {
          throw new ForbiddenException('Only an owner can revoke ownership');
        }
        await this.assertNotLastActiveOwner(tx, orgId);
      }
      return tx.membership.update({
        where: { orgId_userId: { orgId, userId } },
        data: { disabledAt: new Date() },
      });
    });
  }

  /**
   * JWT path: JIT upsert User by idpSubject, then load Membership. Missing or
   * disabled membership → 403. Role comes only from Membership. `sub` is never
   * returned as `userId`.
   */
  async resolveJwt(input: ResolveJwtRequest) {
    // Persist the User even when Membership is missing (403). Users are not
    // RLS-scoped; doing this inside withOrg would roll back the JIT upsert.
    const user = await this.upsertUserFromClaims(this.prisma, input);
    if (user.disabledAt) {
      throw new ForbiddenException('No organization membership');
    }

    return this.prisma.withOrg(input.orgId, async (tx) => {
      let membership = await tx.membership.findUnique({
        where: { orgId_userId: { orgId: input.orgId, userId: user.id } },
      });
      if (!membership || membership.disabledAt) {
        membership = await this.acceptPendingInvite(tx, input.orgId, user, membership);
      }
      if (!membership || membership.disabledAt) {
        throw new ForbiddenException('No organization membership');
      }

      const role = Role.safeParse(membership.role);
      if (!role.success) {
        throw new ForbiddenException('No organization membership');
      }

      return { userId: user.id, orgId: input.orgId, role: role.data };
    });
  }

  private async upsertUserFromClaims(
    db: { user: PrismaService['user'] },
    input: ResolveJwtRequest,
  ) {
    const email = input.email?.trim().toLowerCase();
    const name = input.name?.trim();
    const existing = await db.user.findUnique({ where: { idpSubject: input.sub } });
    if (existing) {
      const data: { email?: string; name?: string } = {};
      if (email && email !== existing.email) {
        const taken = await db.user.findUnique({ where: { email } });
        if (!taken) data.email = email;
      }
      if (name && name !== existing.name) data.name = name;
      if (Object.keys(data).length === 0) return existing;
      return db.user.update({ where: { id: existing.id }, data });
    }

    if (!email) {
      throw new ForbiddenException('No organization membership');
    }
    const taken = await db.user.findUnique({ where: { email } });
    if (taken) {
      throw new ForbiddenException('No organization membership');
    }

    return db.user.create({
      data: {
        email,
        name: name && name.length > 0 ? name : email.split('@')[0]!,
        idpSubject: input.sub,
      },
    });
  }

  private async acceptPendingInvite(
    tx: PrismaTransaction,
    orgId: string,
    user: { id: string; email: string },
    existing: {
      orgId: string;
      userId: string;
      role: string;
      disabledAt: Date | null;
      createdAt: Date;
    } | null,
  ) {
    const invite = await tx.membershipInvite.findFirst({
      where: {
        orgId,
        email: user.email.toLowerCase(),
        acceptedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });
    if (!invite) return existing;

    const role = Role.safeParse(invite.role);
    if (!role.success) return existing;

    await tx.membershipInvite.update({
      where: { id: invite.id },
      data: { acceptedAt: new Date() },
    });

    if (existing) {
      return tx.membership.update({
        where: { orgId_userId: { orgId, userId: user.id } },
        data: { role: role.data, disabledAt: null },
      });
    }
    return tx.membership.create({
      data: { orgId, userId: user.id, role: role.data },
    });
  }

  private requireUserId(userId: string): void {
    if (!UserId.safeParse(userId).success) {
      throw new BadRequestException('Invalid user id');
    }
  }

  private async requireMembership(tx: PrismaTransaction, orgId: string, userId: string) {
    const membership = await tx.membership.findUnique({
      where: { orgId_userId: { orgId, userId } },
    });
    // RLS hide and a genuine miss look the same — never P2025 / 500.
    if (!membership) throw new NotFoundException('Member not found');
    return membership;
  }

  private assertOwnerRoleChange(actorRole: Role, from: string, to: Role): void {
    if (to === 'owner' && actorRole !== 'owner') {
      throw new ForbiddenException('Only an owner can grant ownership');
    }
    if (from === 'owner' && to !== 'owner' && actorRole !== 'owner') {
      throw new ForbiddenException('Only an owner can revoke ownership');
    }
  }

  private async assertNotLastActiveOwner(tx: PrismaTransaction, orgId: string): Promise<void> {
    const owners = await tx.membership.count({
      where: { orgId, role: 'owner', disabledAt: null },
    });
    if (owners <= 1) {
      throw new ForbiddenException('Cannot modify the last owner');
    }
  }

  private hash(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}

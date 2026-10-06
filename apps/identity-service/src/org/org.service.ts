import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  type OnModuleDestroy,
} from '@nestjs/common';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { loadEnv } from '@ctem/config';
import { PrismaClient, PrismaService, type PrismaTransaction } from '@ctem/db';
import {
  CreateOrgRequest,
  CreateOrgResponse,
  InviteMemberRequest,
  OrgId,
  ResolveJwtRequest,
  ResolveMembershipsRequest,
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
export class OrgService implements OnModuleDestroy {
  private ownerDb?: PrismaClient;

  constructor(private readonly prisma: PrismaService) {}

  async onModuleDestroy(): Promise<void> {
    await this.ownerDb?.$disconnect();
  }

  /**
   * Membership is RLS-scoped and fails closed when no org GUC is set. A JWT
   * with no org_id cannot name the tenant, so this read uses the platform
   * owner role (the same role that owns `verify_api_token`) and always filters
   * by this user's id.
   */
  private platformOwner(): PrismaClient {
    if (!this.ownerDb) {
      const env = loadEnv();
      this.ownerDb = new PrismaClient({
        datasources: { db: { url: env.DATABASE_URL } },
        log: env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
      });
    }
    return this.ownerDb;
  }

  /**
   * Writes the org, its owner membership, and the default policies on the
   * caller's transaction. Does not open a client or a transaction.
   * `viaSignup: true` is set only here, and only `createOrgForSubject` calls this.
   */
  private async createOrg(tx: PrismaTransaction, name: string, slug: string, ownerUserId: string) {
    const id = randomUUID();
    // RLS WITH CHECK requires the GUC to equal the new org id. The id is
    // generated here; the client never supplies it.
    await tx.$executeRawUnsafe(`SELECT set_config('app.current_org_id', $1, true)`, id);
    return tx.organization.create({
      data: {
        id,
        name,
        slug,
        memberships: { create: { userId: ownerUserId, role: 'owner', viaSignup: true } },
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
    });
  }

  /**
   * JWT with no org_id. JIT-upserts the user, then returns only that user's
   * active membership org ids and roles. Disabled memberships do not count.
   */
  async resolveActiveMemberships(input: ResolveMembershipsRequest) {
    const user = await this.upsertUserFromClaims(this.prisma, input);
    if (user.disabledAt) {
      throw new ForbiddenException('No organization membership');
    }
    const memberships = await this.prisma.unsafeCrossTenant(
      'resolve single membership when JWT has no org_id',
      async () => this.readActiveMemberships(this.platformOwner(), user.id),
    );
    return { userId: user.id, memberships };
  }

  /**
   * First org for a user who already exists (JIT from the verified `sub`).
   * Rejects a second active membership and turns a slug collision into 409.
   */
  async createOrgForSubject(sub: string, name: string, slug: string) {
    const parsed = CreateOrgRequest.safeParse({ name, slug });
    if (!parsed.success) throw new BadRequestException('Validation failed');

    const user = await this.prisma.user.findUnique({ where: { idpSubject: sub } });
    if (!user || user.disabledAt) throw new ForbiddenException('No organization');

    try {
      return await this.prisma.unsafeCrossTenant('org bootstrap has no tenant context yet', () =>
        this.platformOwner().$transaction(async (tx) => {
          await tx.$executeRawUnsafe(
            `SELECT pg_advisory_xact_lock(hashtext('ctem-create-org:' || $1)::bigint)`,
            user.id,
          );
          const active = await this.readActiveMemberships(tx, user.id);
          if (active.length > 0) {
            throw new ConflictException('User already belongs to an organization');
          }
          const org = await this.createOrg(tx, parsed.data.name, parsed.data.slug, user.id);
          return CreateOrgResponse.parse({
            id: org.id,
            name: org.name,
            slug: org.slug,
            plan: org.plan,
          });
        }),
      );
    } catch (err) {
      if (err instanceof ConflictException || err instanceof ForbiddenException) throw err;
      // Postgres aborts the transaction on a unique violation. Map it here,
      // outside the interactive transaction — never retry inside it. An
      // unresolvable Membership target does one owner-client read below.
      const conflict = await resolveCreateOrgUniqueViolation(err, () =>
        this.hasActiveSignupMembership(user.id),
      );
      if (conflict) throw conflict;
      throw err;
    }
  }

  /** One owner-client read. Call only after the create-org transaction has aborted. */
  private async hasActiveSignupMembership(userId: string): Promise<boolean> {
    const row = await this.platformOwner().membership.findFirst({
      where: { userId, viaSignup: true, disabledAt: null },
      select: { userId: true },
    });
    return row !== null;
  }

  private async readActiveMemberships(
    db: PrismaClient | PrismaTransaction,
    userId: string,
  ): Promise<Array<{ orgId: string; role: Role }>> {
    if (!UserId.safeParse(userId).success) return [];
    const rows = await db.membership.findMany({
      where: { userId, disabledAt: null },
      select: { orgId: true, role: true },
    });
    const memberships: Array<{ orgId: string; role: Role }> = [];
    for (const row of rows) {
      const orgId = OrgId.safeParse(row.orgId);
      const role = Role.safeParse(row.role);
      if (!orgId.success || !role.success) continue;
      memberships.push({ orgId: orgId.data, role: role.data });
    }
    return memberships;
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
    input: { sub: string; email?: string; name?: string },
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
      viaSignup: boolean;
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
        data: { role: role.data, disabledAt: null, viaSignup: false },
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

/** Partial unique index. Prisma cannot model it; it lives only in the signup migration. */
export const SIGNUP_MEMBERSHIP_INDEX = 'memberships_userId_signup_active_key';

const SLUG_TAKEN = 'Organization slug is already taken';
const ALREADY_IN_ORG = 'User already belongs to an organization';

interface UniqueViolationMeta {
  target?: unknown;
  modelName?: unknown;
  constraint?: unknown;
}

function isUniqueViolation(err: unknown): err is { code: 'P2002'; meta?: UniqueViolationMeta } {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code: unknown }).code === 'P2002'
  );
}

function targetParts(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (!Array.isArray(value)) return [];
  return value.filter((part): part is string => typeof part === 'string');
}

function namesToken(names: string[], token: string): boolean {
  return names.some((name) => name === token || name.split(/[^A-Za-z0-9]+/).includes(token));
}

function isMembershipModel(meta: UniqueViolationMeta | undefined): boolean {
  const model = typeof meta?.modelName === 'string' ? meta.modelName : '';
  return model === 'Membership' || model === 'memberships';
}

function namesExplicitSignup(meta: UniqueViolationMeta | undefined, names: string[]): boolean {
  if (
    names.some((name) => name === SIGNUP_MEMBERSHIP_INDEX || name.includes(SIGNUP_MEMBERSHIP_INDEX))
  ) {
    return true;
  }
  if (names.includes('memberships.userId')) return true;
  const target = targetParts(meta?.target);
  return isMembershipModel(meta) && target.length === 1 && target[0] === 'userId';
}

/**
 * `target` can be null when the violating insert ran under row-level security.
 * That happens for declared indexes too (seen on
 * `integrations_orgId_provider_displayName_key`). `platformOwner()` bypasses
 * RLS, so a create-org insert usually reports a concrete target. A null or
 * otherwise unresolvable Membership target is not assumed to be the signup
 * index; the caller re-checks whether an active `viaSignup` row exists.
 */
function membershipTargetUnresolvable(meta: UniqueViolationMeta | undefined): boolean {
  if (!isMembershipModel(meta)) return false;
  const target = meta?.target;
  if (target == null) return true;
  return targetParts(target).length === 0;
}

export type CreateOrgUniqueMapping =
  { action: 'conflict'; exception: ConflictException } | { action: 'recheck-active-signup' };

/**
 * Create-org P2002 → 409. Exact targets only, never a 500:
 * slug → slug taken; the signup index (or `memberships.userId`) → already in an org;
 * a Membership target that is null or unresolvable → `recheck-active-signup`;
 * any other unique target → generic Conflict.
 * Returns null when `err` is not a P2002.
 */
export function mapCreateOrgUniqueViolation(err: unknown): CreateOrgUniqueMapping | null {
  if (!isUniqueViolation(err)) return null;
  const names = [...targetParts(err.meta?.target), ...targetParts(err.meta?.constraint)];
  if (namesToken(names, 'slug')) {
    return { action: 'conflict', exception: new ConflictException(SLUG_TAKEN) };
  }
  if (namesExplicitSignup(err.meta, names)) {
    return { action: 'conflict', exception: new ConflictException(ALREADY_IN_ORG) };
  }
  if (membershipTargetUnresolvable(err.meta)) return { action: 'recheck-active-signup' };
  return { action: 'conflict', exception: new ConflictException('Conflict') };
}

/**
 * Finish a create-org P2002 outside the aborted transaction.
 * `readActiveViaSignup` runs only for an unresolvable Membership target,
 * and it must be a single owner-client read.
 */
export async function resolveCreateOrgUniqueViolation(
  err: unknown,
  readActiveViaSignup: () => Promise<boolean>,
): Promise<ConflictException | null> {
  const mapped = mapCreateOrgUniqueViolation(err);
  if (!mapped) return null;
  if (mapped.action === 'conflict') return mapped.exception;
  const active = await readActiveViaSignup();
  return new ConflictException(active ? ALREADY_IN_ORG : 'Conflict');
}

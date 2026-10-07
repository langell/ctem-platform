import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpException,
  Injectable,
  NotFoundException,
  type OnModuleDestroy,
} from '@nestjs/common';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
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
/** `randomBytes(32).toString('base64url')` is 43 characters. */
const INVITE_TOKEN = /^ctem_inv_[A-Za-z0-9_-]{43}$/;

/**
 * Tenant identity: Membership is the AuthZ source of truth. Keycloak authenticates;
 * realm roles never mint a Membership. An invite becomes a Membership through the
 * token link, or through verified email-match when the user has no active membership.
 */

/** One shared normalizer for invite create, user upsert, and both accept paths. */
export function normalizeEmail(email: string | undefined | null): string | undefined {
  if (typeof email !== 'string') return undefined;
  const normalized = email.trim().toLowerCase();
  return normalized.length > 0 ? normalized : undefined;
}
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
   * Verified email-match may consume exactly one pending invite when there
   * is no active membership. An unverified email never joins.
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
    if (
      memberships.length === 0 &&
      input.emailVerified === true &&
      normalizeEmail(input.email) === normalizeEmail(user.email)
    ) {
      const joined = await this.acceptSingleVerifiedInvite(user);
      if (joined && joined.length > 0) {
        return { userId: user.id, memberships: joined };
      }
    }
    return { userId: user.id, memberships };
  }

  /**
   * Mesh accept. Possession of the invite token plus a canonical email match.
   * Does not require email_verified. A refusal writes nothing.
   */
  async acceptInviteByToken(sub: string, token: string): Promise<{ orgId: string; role: Role }> {
    if (!INVITE_TOKEN.test(token)) throw inviteInvalid();

    const user = await this.prisma.user.findUnique({ where: { idpSubject: sub } });
    if (!user || user.disabledAt) throw new ForbiddenException('No organization membership');

    const tokenHash = this.hash(token);
    const located = await this.platformOwner().membershipInvite.findUnique({
      where: { tokenHash },
    });
    if (!timingSafeDigestEqual(located?.tokenHash, tokenHash) || !located) {
      throw inviteInvalid();
    }

    try {
      return await this.prisma.unsafeCrossTenant('invite accept has no tenant context yet', () =>
        this.platformOwner().$transaction(async (tx) => {
          await lockMembershipUser(tx, user.id);
          const invite = await tx.membershipInvite.findUnique({ where: { id: located.id } });
          if (!invite || invite.expiresAt.getTime() <= Date.now()) throw inviteInvalid();

          const active = await this.readActiveMemberships(tx, user.id);
          if (invite.acceptedAt) {
            const here = active.find((membership) => membership.orgId === invite.orgId);
            if (here) return { orgId: invite.orgId, role: here.role };
            throw inviteInvalid();
          }

          if (normalizeEmail(user.email) !== normalizeEmail(invite.email)) {
            throw inviteEmailMismatch();
          }

          if (active.some((membership) => membership.orgId !== invite.orgId)) {
            throw inviteAlreadyInOrg();
          }
          const here = active.find((membership) => membership.orgId === invite.orgId);
          if (here) {
            await tx.membershipInvite.update({
              where: { id: invite.id },
              data: { acceptedAt: new Date() },
            });
            return { orgId: invite.orgId, role: here.role };
          }

          const role = await this.grantInviteMembership(tx, user.id, invite);
          return { orgId: invite.orgId, role };
        }),
      );
    } catch (err) {
      if (err instanceof HttpException) throw err;
      const conflict = await resolveMembershipUniqueViolation(
        err,
        () => this.hasActiveMembership(user.id),
        () => inviteAlreadyInOrg(),
        { mapSlug: false },
      );
      if (conflict) throw conflict;
      throw err;
    }
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
          await lockMembershipUser(tx, user.id);
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
        this.hasActiveMembership(user.id),
      );
      if (conflict) throw conflict;
      throw err;
    }
  }

  /** One owner-client read. Call only after the membership transaction has aborted. */
  private async hasActiveMembership(userId: string): Promise<boolean> {
    const row = await this.platformOwner().membership.findFirst({
      where: { userId, disabledAt: null },
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
    const email = normalizeEmail(input.email);
    if (!email) throw new BadRequestException('Validation failed');
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
    // A present org_id is a read-only consistency check. It does not accept invites.
    const user = await this.upsertUserFromClaims(this.prisma, input);
    if (user.disabledAt) {
      throw new ForbiddenException('No organization membership');
    }

    return this.prisma.withOrg(input.orgId, async (tx) => {
      const membership = await tx.membership.findUnique({
        where: { orgId_userId: { orgId: input.orgId, userId: user.id } },
      });
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

  /**
   * Verified email, no active membership, exactly one pending org.
   * Zero or several orgs leave every invite pending and return null.
   * A lost race returns the membership that won and leaves the invite pending.
   */
  private async acceptSingleVerifiedInvite(user: {
    id: string;
    email: string;
  }): Promise<Array<{ orgId: string; role: Role }> | null> {
    try {
      return await this.prisma.unsafeCrossTenant(
        'verified email-match accept has no tenant context yet',
        () =>
          this.platformOwner().$transaction(async (tx) => {
            await lockMembershipUser(tx, user.id);
            const active = await this.readActiveMemberships(tx, user.id);
            if (active.length > 0) return active;

            const email = normalizeEmail(user.email);
            if (!email) return null;
            const pending = await tx.membershipInvite.findMany({
              where: { email, acceptedAt: null, expiresAt: { gt: new Date() } },
              orderBy: { createdAt: 'desc' },
            });
            const newestByOrg = new Map<string, (typeof pending)[number]>();
            for (const invite of pending) {
              if (!Role.safeParse(invite.role).success) continue;
              if (!newestByOrg.has(invite.orgId)) newestByOrg.set(invite.orgId, invite);
            }
            if (newestByOrg.size !== 1) return null;
            const invite = [...newestByOrg.values()][0]!;
            const role = await this.grantInviteMembership(tx, user.id, invite);
            return [{ orgId: invite.orgId, role }];
          }),
      );
    } catch (err) {
      if (!(err instanceof HttpException)) {
        const kind = classifyMembershipUniqueViolation(err);
        if (kind === 'one-active' || kind === 'recheck') {
          const active = await this.readActiveMemberships(this.platformOwner(), user.id);
          if (active.length > 0) return active;
          const conflict = await resolveMembershipUniqueViolation(
            err,
            () => this.hasActiveMembership(user.id),
            () => inviteAlreadyInOrg(),
            { mapSlug: false },
          );
          if (conflict) throw conflict;
        }
        if (kind === 'conflict' || kind === 'slug') throw new ConflictException('Conflict');
      }
      throw err;
    }
  }

  /** Insert or re-enable, then consume the invite. Caller holds the user lock. */
  private async grantInviteMembership(
    tx: PrismaTransaction,
    userId: string,
    invite: { id: string; orgId: string; role: string },
  ): Promise<Role> {
    const role = Role.safeParse(invite.role);
    if (!role.success) throw inviteInvalid();
    await tx.$executeRawUnsafe(`SELECT set_config('app.current_org_id', $1, true)`, invite.orgId);
    const existing = await tx.membership.findUnique({
      where: { orgId_userId: { orgId: invite.orgId, userId } },
    });
    if (existing && !existing.disabledAt) {
      await tx.membershipInvite.update({
        where: { id: invite.id },
        data: { acceptedAt: new Date() },
      });
      const parsed = Role.safeParse(existing.role);
      if (!parsed.success) throw inviteInvalid();
      return parsed.data;
    }
    if (existing) {
      await tx.membership.update({
        where: { orgId_userId: { orgId: invite.orgId, userId } },
        data: { role: role.data, disabledAt: null, viaSignup: false },
      });
    } else {
      await tx.membership.create({
        data: { orgId: invite.orgId, userId, role: role.data, viaSignup: false },
      });
    }
    await tx.membershipInvite.update({
      where: { id: invite.id },
      data: { acceptedAt: new Date() },
    });
    return role.data;
  }

  private async upsertUserFromClaims(
    db: { user: PrismaService['user'] },
    input: { sub: string; email?: string; name?: string },
  ) {
    const email = normalizeEmail(input.email);
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

/** Partial unique index. Prisma cannot model it; it lives only in the one-active migration. */
export const ACTIVE_MEMBERSHIP_INDEX = 'memberships_userId_active_key';

const SLUG_TAKEN = 'Organization slug is already taken';
const ALREADY_IN_ORG = 'User already belongs to an organization';
const INVITE_ALREADY_DETAIL =
  'Ask an admin of your current organization to remove you, then open this invite again.';

export const INVITE_ALREADY_IN_ORG_TYPE = 'urn:ctem:problem:invite-already-in-org';
export const INVITE_EMAIL_MISMATCH_TYPE = 'urn:ctem:problem:invite-email-mismatch';
export const INVITE_INVALID_TYPE = 'urn:ctem:problem:invite-invalid';

interface UniqueViolationMeta {
  target?: unknown;
  modelName?: unknown;
  constraint?: unknown;
}

export type MembershipUniqueClass = 'slug' | 'one-active' | 'recheck' | 'conflict';

export type CreateOrgUniqueMapping =
  | { action: 'conflict'; exception: ConflictException }
  | { action: 'recheck' };

function inviteProblem(status: number, type: string, title: string, detail: string): HttpException {
  return new HttpException({ type, title, detail, message: detail }, status);
}

export function inviteAlreadyInOrg(): HttpException {
  return inviteProblem(
    409,
    INVITE_ALREADY_IN_ORG_TYPE,
    'You already belong to an organization',
    INVITE_ALREADY_DETAIL,
  );
}

export function inviteEmailMismatch(): HttpException {
  return inviteProblem(
    403,
    INVITE_EMAIL_MISMATCH_TYPE,
    'This invite was sent to a different email address',
    'This invite was sent to a different email address',
  );
}

export function inviteInvalid(): HttpException {
  return inviteProblem(
    404,
    INVITE_INVALID_TYPE,
    'Invite invalid',
    'This invite link is invalid or has expired.',
  );
}

async function lockMembershipUser(tx: PrismaTransaction, userId: string): Promise<void> {
  await tx.$executeRawUnsafe(
    `SELECT pg_advisory_xact_lock(hashtext('ctem-create-org:' || $1)::bigint)`,
    userId,
  );
}

/** Compare hex digests in constant time. A missing stored hash still compares, then fails. */
function timingSafeDigestEqual(stored: string | undefined, computed: string): boolean {
  const left = Buffer.from(stored ?? '0'.repeat(computed.length), 'hex');
  const right = Buffer.from(computed, 'hex');
  if (left.length === 0 || left.length !== right.length) return false;
  const equal = timingSafeEqual(left, right);
  return stored !== undefined && equal;
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

/**
 * `target` can be null when the violating insert ran under row-level security.
 * `platformOwner()` bypasses RLS and usually reports `['userId']`. A null,
 * empty, or missing Membership target is not assumed to be the one-active
 * index; the caller re-checks whether any active membership exists.
 */
function membershipTargetUnresolvable(meta: UniqueViolationMeta | undefined): boolean {
  if (!isMembershipModel(meta)) return false;
  const target = meta?.target;
  if (target == null) return true;
  return targetParts(target).length === 0;
}

/**
 * Classify a P2002. The caller picks the 409 text.
 * slug; Membership target exactly `['userId']` or a name containing
 * `memberships_userId_active_key` → one-active; a null, empty, or missing
 * Membership target → recheck; anything else, including the membership PK
 * and a tokenHash collision → conflict. Returns null when `err` is not a P2002.
 */
export function classifyMembershipUniqueViolation(err: unknown): MembershipUniqueClass | null {
  if (!isUniqueViolation(err)) return null;
  const names = [...targetParts(err.meta?.target), ...targetParts(err.meta?.constraint)];
  if (namesToken(names, 'slug')) return 'slug';
  if (names.some((name) => name.includes(ACTIVE_MEMBERSHIP_INDEX))) return 'one-active';
  const target = targetParts(err.meta?.target);
  if (isMembershipModel(err.meta) && target.length === 1 && target[0] === 'userId') {
    return 'one-active';
  }
  if (membershipTargetUnresolvable(err.meta)) return 'recheck';
  return 'conflict';
}

/**
 * Create-org view of {@link classifyMembershipUniqueViolation}.
 * slug and one-active are conflicts; an unresolvable Membership target is `recheck`.
 */
export function mapCreateOrgUniqueViolation(err: unknown): CreateOrgUniqueMapping | null {
  const kind = classifyMembershipUniqueViolation(err);
  if (!kind) return null;
  if (kind === 'slug') return { action: 'conflict', exception: new ConflictException(SLUG_TAKEN) };
  if (kind === 'one-active') {
    return { action: 'conflict', exception: new ConflictException(ALREADY_IN_ORG) };
  }
  if (kind === 'recheck') return { action: 'recheck' };
  return { action: 'conflict', exception: new ConflictException('Conflict') };
}

/**
 * Finish a P2002 outside the aborted transaction.
 * `readHasActiveMembership` runs only for `recheck`, and it must be one owner-client read.
 * `mapSlug: false` turns a slug violation into a generic Conflict (accept paths).
 */
export async function resolveMembershipUniqueViolation(
  err: unknown,
  readHasActiveMembership: () => Promise<boolean>,
  oneActiveException: () => HttpException,
  options?: { mapSlug?: boolean },
): Promise<HttpException | null> {
  const kind = classifyMembershipUniqueViolation(err);
  if (!kind) return null;
  if (kind === 'slug') {
    if (options?.mapSlug === false) return new ConflictException('Conflict');
    return new ConflictException(SLUG_TAKEN);
  }
  if (kind === 'one-active') return oneActiveException();
  if (kind === 'recheck') {
    const active = await readHasActiveMembership();
    return active ? oneActiveException() : new ConflictException('Conflict');
  }
  return new ConflictException('Conflict');
}

/**
 * Finish a create-org P2002 outside the aborted transaction.
 * The recheck reads any active membership, not only `viaSignup` rows.
 */
export async function resolveCreateOrgUniqueViolation(
  err: unknown,
  readHasActiveMembership: () => Promise<boolean>,
): Promise<ConflictException | null> {
  const resolved = await resolveMembershipUniqueViolation(
    err,
    readHasActiveMembership,
    () => new ConflictException(ALREADY_IN_ORG),
  );
  if (!resolved) return null;
  return resolved instanceof ConflictException ? resolved : new ConflictException(ALREADY_IN_ORG);
}

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ConflictException, ForbiddenException, HttpException } from '@nestjs/common';
import { ROLE_PERMISSIONS, type Principal, type Role } from '@ctem/contracts';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import {
  appClient,
  createOrg,
  createUserWithMembership,
  deleteOrgCascade,
  ownerClient,
  uniqueSlug,
  withOrg,
} from '@ctem/testing';
import {
  classifyMembershipUniqueViolation,
  inviteAlreadyInOrg,
  OrgService,
  resolveCreateOrgUniqueViolation,
  resolveMembershipUniqueViolation,
} from './org.service';

const ALREADY_IN_ORG = 'User already belongs to an organization';
const INVITE_ALREADY = 'urn:ctem:problem:invite-already-in-org';
const INVITE_MISMATCH = 'urn:ctem:problem:invite-email-mismatch';
const INVITE_INVALID = 'urn:ctem:problem:invite-invalid';

function actor(orgId: string, userId: string, role: Role): Principal {
  return {
    userId,
    orgId,
    role,
    permissions: ROLE_PERMISSIONS[role],
    serviceAccount: null,
    traceId: 'invite-accept',
  };
}

function problem(err: unknown) {
  expect(err).toBeInstanceOf(HttpException);
  const http = err as HttpException;
  const body = http.getResponse() as { type?: string; title?: string; detail?: string; message?: string };
  return { status: http.getStatus(), body, text: JSON.stringify(body) };
}

function chunkText(chunk: unknown): string {
  if (typeof chunk === 'string') return chunk;
  if (Buffer.isBuffer(chunk)) return chunk.toString('utf8');
  return String(chunk);
}

function pinoStream(logger: object): { write: (chunk: string) => boolean } {
  let current: object | null = logger;
  while (current) {
    for (const sym of Object.getOwnPropertySymbols(current)) {
      if (sym.description === 'pino.stream') {
        return (current as Record<symbol, { write: (chunk: string) => boolean }>)[sym];
      }
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw new Error('pino stream not found');
}

function captureLogs() {
  const lines: string[] = [];
  const stream = pinoStream(rootLogger);
  const origPino = stream.write.bind(stream);
  stream.write = (chunk: string) => {
    lines.push(chunkText(chunk));
    return origPino(chunk);
  };
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((chunk: unknown, ...args: unknown[]) => {
    lines.push(chunkText(chunk));
    return origOut(chunk as never, ...(args as never[]));
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: unknown, ...args: unknown[]) => {
    lines.push(chunkText(chunk));
    return origErr(chunk as never, ...(args as never[]));
  }) as typeof process.stderr.write;
  /* eslint-disable no-console */
  const origConsoleLog = console.log.bind(console);
  const origConsoleError = console.error.bind(console);
  console.log = (...args: unknown[]) => {
    lines.push(args.map((arg) => chunkText(arg)).join(' '));
    origConsoleLog(...args);
  };
  console.error = (...args: unknown[]) => {
    lines.push(args.map((arg) => chunkText(arg)).join(' '));
    origConsoleError(...args);
  };
  /* eslint-enable no-console */
  return {
    text: () => lines.join('\n'),
    restore: () => {
      stream.write = origPino;
      process.stdout.write = origOut;
      process.stderr.write = origErr;
      /* eslint-disable no-console */
      console.log = origConsoleLog;
      console.error = origConsoleError;
      /* eslint-enable no-console */
    },
  };
}

describe('invite accept', () => {
  let owner: PrismaClient;
  let prismaA: PrismaService;
  let prismaB: PrismaService;
  let serviceA: OrgService;
  let serviceB: OrgService;
  const orgIds: string[] = [];
  const userIds: string[] = [];

  beforeAll(async () => {
    owner = ownerClient();
    prismaA = new PrismaService();
    prismaB = new PrismaService();
    serviceA = new OrgService(prismaA);
    serviceB = new OrgService(prismaB);
  });

  afterAll(async () => {
    for (const orgId of orgIds) await deleteOrgCascade(owner, orgId);
    if (userIds.length) await owner.user.deleteMany({ where: { id: { in: userIds } } });
    await serviceA.onModuleDestroy();
    await serviceB.onModuleDestroy();
    await Promise.all([owner.$disconnect(), prismaA.$disconnect(), prismaB.$disconnect()]);
  });

  async function freshUser(label: string) {
    const sub = `idp|${uniqueSlug(label)}`;
    const email = `${uniqueSlug(label)}@test.local`;
    const user = await serviceA.resolveActiveMemberships({ sub, email, name: label });
    userIds.push(user.userId);
    return { sub, email, userId: user.userId };
  }

  async function invitingOrg() {
    const org = await createOrg(owner);
    orgIds.push(org.id);
    const inviter = await createUserWithMembership(owner, org.id, 'owner');
    userIds.push(inviter.id);
    return { org, inviter };
  }

  async function inviteFor(orgId: string, inviterId: string, email: string, role: Role = 'developer') {
    return serviceA.invite(orgId, actor(orgId, inviterId, 'owner'), { email, role });
  }

  it('token accept by a new user creates one membership with viaSignup false', async () => {
    const user = await freshUser('token-new');
    const { org, inviter } = await invitingOrg();
    const invite = await inviteFor(org.id, inviter.id, user.email, 'developer');

    const accepted = await serviceA.acceptInviteByToken(user.sub, invite.token);
    expect(accepted).toEqual({ orgId: org.id, role: 'developer' });

    const rows = await owner.membership.findMany({ where: { userId: user.userId } });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      orgId: org.id,
      role: 'developer',
      viaSignup: false,
      disabledAt: null,
    });
    const stored = await owner.membershipInvite.findFirst({ where: { email: user.email, orgId: org.id } });
    expect(stored?.acceptedAt).not.toBeNull();
    expect(stored?.tokenHash).not.toBe(invite.token);
  });

  it('double-click accept (5 concurrent) returns the same org, one membership, invite consumed once, no prisma:error', async () => {
    const user = await freshUser('double');
    const { org, inviter } = await invitingOrg();
    const invite = await inviteFor(org.id, inviter.id, user.email);
    const calls = [
      () => serviceA.acceptInviteByToken(user.sub, invite.token),
      () => serviceB.acceptInviteByToken(user.sub, invite.token),
      () => serviceA.acceptInviteByToken(user.sub, invite.token),
      () => serviceB.acceptInviteByToken(user.sub, invite.token),
      () => serviceA.acceptInviteByToken(user.sub, invite.token),
    ];
    const captured = captureLogs();
    try {
      const results = await Promise.all(calls.map((call) => call()));
      expect(results).toEqual(calls.map(() => ({ orgId: org.id, role: 'developer' })));
      expect(captured.text()).not.toMatch(/prisma:error/);
    } finally {
      captured.restore();
    }
    const rows = await owner.membership.findMany({ where: { userId: user.userId, disabledAt: null } });
    expect(rows).toHaveLength(1);
    const invites = await owner.membershipInvite.findMany({ where: { email: user.email, orgId: org.id } });
    expect(invites).toHaveLength(1);
    expect(invites[0]?.acceptedAt).not.toBeNull();
  });

  it('accept by a user with an active org is refused and consumes nothing', async () => {
    const user = await freshUser('busy');
    const home = await serviceA.createOrgForSubject(user.sub, 'Home', uniqueSlug('busy-home'));
    orgIds.push(home.id);
    const { org, inviter } = await invitingOrg();
    const invite = await inviteFor(org.id, inviter.id, user.email);
    const before = await owner.membershipInvite.findFirst({ where: { email: user.email, orgId: org.id } });

    let failure: unknown;
    try {
      await serviceB.acceptInviteByToken(user.sub, invite.token);
    } catch (err) {
      failure = err;
    }
    const refused = problem(failure);
    expect(refused.status).toBe(409);
    expect(refused.body.type).toBe(INVITE_ALREADY);

    const after = await owner.membershipInvite.findFirst({ where: { email: user.email, orgId: org.id } });
    expect(after?.tokenHash).toBe(before?.tokenHash);
    expect(after?.expiresAt).toEqual(before?.expiresAt);
    expect(after?.acceptedAt).toBeNull();
    const inInviting = await owner.membership.findUnique({
      where: { orgId_userId: { orgId: org.id, userId: user.userId } },
    });
    expect(inInviting).toBeNull();
    const active = await owner.membership.findMany({ where: { userId: user.userId, disabledAt: null } });
    expect(active.map((row) => row.orgId)).toEqual([home.id]);
  });

  it('non-owner removed from B by B admin then accepts A', async () => {
    const orgB = await createOrg(owner);
    orgIds.push(orgB.id);
    const admin = await createUserWithMembership(owner, orgB.id, 'admin');
    userIds.push(admin.id);
    const orgA = (await invitingOrg()).org;
    const inviter = await owner.membership.findFirst({ where: { orgId: orgA.id, role: 'owner' } });
    expect(inviter).not.toBeNull();

    const byToken = await freshUser('leave-token');
    await owner.membership.create({
      data: { orgId: orgB.id, userId: byToken.userId, role: 'developer', viaSignup: false },
    });
    await serviceB.disable(orgB.id, actor(orgB.id, admin.id, 'admin'), byToken.userId);
    const tokenInvite = await inviteFor(orgA.id, inviter!.userId, byToken.email);
    const accepted = await serviceA.acceptInviteByToken(byToken.sub, tokenInvite.token);
    expect(accepted).toEqual({ orgId: orgA.id, role: 'developer' });
    const tokenA = await owner.membership.findUnique({
      where: { orgId_userId: { orgId: orgA.id, userId: byToken.userId } },
    });
    const tokenB = await owner.membership.findUnique({
      where: { orgId_userId: { orgId: orgB.id, userId: byToken.userId } },
    });
    expect(tokenA).toMatchObject({ viaSignup: false, disabledAt: null, role: 'developer' });
    expect(tokenB?.disabledAt).not.toBeNull();

    const byEmail = await freshUser('leave-email');
    await owner.membership.create({
      data: { orgId: orgB.id, userId: byEmail.userId, role: 'developer', viaSignup: false },
    });
    await serviceA.disable(orgB.id, actor(orgB.id, admin.id, 'admin'), byEmail.userId);
    await inviteFor(orgA.id, inviter!.userId, byEmail.email);
    const resolved = await serviceB.resolveActiveMemberships({
      sub: byEmail.sub,
      email: byEmail.email,
      emailVerified: true,
    });
    expect(resolved.memberships).toEqual([{ orgId: orgA.id, role: 'developer' }]);
    const emailA = await owner.membership.findUnique({
      where: { orgId_userId: { orgId: orgA.id, userId: byEmail.userId } },
    });
    const emailB = await owner.membership.findUnique({
      where: { orgId_userId: { orgId: orgB.id, userId: byEmail.userId } },
    });
    expect(emailA).toMatchObject({ viaSignup: false, disabledAt: null });
    expect(emailB?.disabledAt).not.toBeNull();
  });

  it('owner of a single-member org is refused', async () => {
    const user = await freshUser('sole');
    const home = await serviceA.createOrgForSubject(user.sub, 'Sole', uniqueSlug('sole'));
    orgIds.push(home.id);
    const { org, inviter } = await invitingOrg();
    const invite = await inviteFor(org.id, inviter.id, user.email, 'owner');
    let failure: unknown;
    try {
      await serviceA.acceptInviteByToken(user.sub, invite.token);
    } catch (err) {
      failure = err;
    }
    expect(problem(failure).status).toBe(409);
    expect(problem(failure).body.type).toBe(INVITE_ALREADY);
    const active = await owner.membership.findMany({ where: { userId: user.userId, disabledAt: null } });
    expect(active).toHaveLength(1);
    expect(active[0]?.orgId).toBe(home.id);
    const pending = await owner.membershipInvite.findFirst({ where: { email: user.email, orgId: org.id } });
    expect(pending?.acceptedAt).toBeNull();
  });

  it('email mismatch is 403 and the invite is unchanged', async () => {
    const invited = await freshUser('mismatch-invited');
    const presenter = await freshUser('mismatch-presenter');
    const { org, inviter } = await invitingOrg();
    const invite = await inviteFor(org.id, inviter.id, invited.email);
    const before = await owner.membershipInvite.findFirst({ where: { email: invited.email, orgId: org.id } });
    let failure: unknown;
    try {
      await serviceA.acceptInviteByToken(presenter.sub, invite.token);
    } catch (err) {
      failure = err;
    }
    const refused = problem(failure);
    expect(refused.status).toBe(403);
    expect(refused.body.type).toBe(INVITE_MISMATCH);
    expect(refused.body.detail).toBe('This invite was sent to a different email address');
    expect(refused.text).not.toContain(invited.email);
    const after = await owner.membershipInvite.findFirst({ where: { email: invited.email, orgId: org.id } });
    expect(after).toMatchObject({
      tokenHash: before?.tokenHash,
      acceptedAt: null,
    });
    expect(after?.expiresAt).toEqual(before?.expiresAt);
  });

  it('unknown, malformed, revoked-shaped (deleted), expired, and accepted-by-another tokens all 404 invite-invalid', async () => {
    const user = await freshUser('invalid');
    const other = await freshUser('invalid-other');
    const { org, inviter } = await invitingOrg();

    const cases: Array<() => Promise<unknown>> = [];

    cases.push(() => serviceA.acceptInviteByToken(user.sub, `ctem_inv_${'a'.repeat(43)}`));
    cases.push(() => serviceA.acceptInviteByToken(user.sub, 'not-a-token'));
    cases.push(() => serviceA.acceptInviteByToken(user.sub, `ctem_inv_${'a'.repeat(42)}`));
    cases.push(() => serviceA.acceptInviteByToken(user.sub, ''));

    const revoked = await inviteFor(org.id, inviter.id, user.email);
    await owner.membershipInvite.deleteMany({ where: { email: user.email, orgId: org.id, acceptedAt: null } });
    cases.push(() => serviceA.acceptInviteByToken(user.sub, revoked.token));

    const expired = await inviteFor(org.id, inviter.id, user.email);
    await owner.membershipInvite.updateMany({
      where: { email: user.email, orgId: org.id, acceptedAt: null },
      data: { expiresAt: new Date(Date.now() - 60_000) },
    });
    cases.push(() => serviceA.acceptInviteByToken(user.sub, expired.token));

    const taken = await freshUser('invalid-taken');
    const takenInvite = await inviteFor(org.id, inviter.id, taken.email);
    await serviceA.acceptInviteByToken(taken.sub, takenInvite.token);
    cases.push(() => serviceB.acceptInviteByToken(other.sub, takenInvite.token));

    for (const call of cases) {
      let failure: unknown;
      try {
        await call();
      } catch (err) {
        failure = err;
      }
      const refused = problem(failure);
      expect(refused.status).toBe(404);
      expect(refused.body.type).toBe(INVITE_INVALID);
    }
  });

  it('email-match: verified joins, unverified does not, active-org user gets their org and invite stays pending, two orgs pending joins neither', async () => {
    const verified = await freshUser('mail-yes');
    const { org, inviter } = await invitingOrg();
    await inviteFor(org.id, inviter.id, verified.email, 'security_analyst');
    const joined = await serviceA.resolveActiveMemberships({
      sub: verified.sub,
      email: verified.email,
      emailVerified: true,
    });
    expect(joined.memberships).toEqual([{ orgId: org.id, role: 'security_analyst' }]);
    const joinedRow = await owner.membership.findUnique({
      where: { orgId_userId: { orgId: org.id, userId: verified.userId } },
    });
    expect(joinedRow).toMatchObject({ viaSignup: false, disabledAt: null });

    const unverified = await freshUser('mail-no');
    const pendingOrg = await invitingOrg();
    await inviteFor(pendingOrg.org.id, pendingOrg.inviter.id, unverified.email);
    for (const emailVerified of [false, undefined] as const) {
      const missed = await serviceA.resolveActiveMemberships({
        sub: unverified.sub,
        email: unverified.email,
        ...(emailVerified === undefined ? {} : { emailVerified }),
      });
      expect(missed.memberships).toEqual([]);
    }
    const stillPending = await owner.membershipInvite.findFirst({
      where: { email: unverified.email, orgId: pendingOrg.org.id },
    });
    expect(stillPending?.acceptedAt).toBeNull();
    expect(
      await owner.membership.findUnique({
        where: { orgId_userId: { orgId: pendingOrg.org.id, userId: unverified.userId } },
      }),
    ).toBeNull();

    const busy = await freshUser('mail-busy');
    const home = await serviceA.createOrgForSubject(busy.sub, 'Busy', uniqueSlug('mail-busy'));
    orgIds.push(home.id);
    const elsewhere = await invitingOrg();
    await inviteFor(elsewhere.org.id, elsewhere.inviter.id, busy.email);
    const stayed = await serviceA.resolveActiveMemberships({
      sub: busy.sub,
      email: busy.email,
      emailVerified: true,
    });
    expect(stayed.memberships).toEqual([{ orgId: home.id, role: 'owner' }]);
    const busyInvite = await owner.membershipInvite.findFirst({
      where: { email: busy.email, orgId: elsewhere.org.id },
    });
    expect(busyInvite?.acceptedAt).toBeNull();

    const both = await freshUser('mail-both');
    const left = await invitingOrg();
    const right = await invitingOrg();
    await inviteFor(left.org.id, left.inviter.id, both.email);
    await inviteFor(right.org.id, right.inviter.id, both.email);
    const neither = await serviceA.resolveActiveMemberships({
      sub: both.sub,
      email: both.email,
      emailVerified: true,
    });
    expect(neither.memberships).toEqual([]);
    const leftInvite = await owner.membershipInvite.findFirst({
      where: { email: both.email, orgId: left.org.id },
    });
    const rightInvite = await owner.membershipInvite.findFirst({
      where: { email: both.email, orgId: right.org.id },
    });
    expect(leftInvite?.acceptedAt).toBeNull();
    expect(rightInvite?.acceptedAt).toBeNull();
  });

  it('create-org before token accept keeps the signup org and refuses the invite', async () => {
    const user = await freshUser('seq-create-token');
    const { org, inviter } = await invitingOrg();
    const invite = await inviteFor(org.id, inviter.id, user.email);
    const created = await serviceA.createOrgForSubject(user.sub, 'First', uniqueSlug('seq-ct'));
    orgIds.push(created.id);
    let failure: unknown;
    try {
      await serviceB.acceptInviteByToken(user.sub, invite.token);
    } catch (err) {
      failure = err;
    }
    expect(problem(failure).body.type).toBe(INVITE_ALREADY);
    const pending = await owner.membershipInvite.findFirst({ where: { email: user.email, orgId: org.id } });
    expect(pending?.acceptedAt).toBeNull();
    const active = await owner.membership.findMany({ where: { userId: user.userId, disabledAt: null } });
    expect(active).toEqual([expect.objectContaining({ orgId: created.id, viaSignup: true })]);
  });

  it('token accept before create-org keeps the invited org', async () => {
    const user = await freshUser('seq-token-create');
    const { org, inviter } = await invitingOrg();
    const invite = await inviteFor(org.id, inviter.id, user.email, 'auditor');
    await serviceA.acceptInviteByToken(user.sub, invite.token);
    await expect(
      serviceB.createOrgForSubject(user.sub, 'Late', uniqueSlug('seq-tc')),
    ).rejects.toThrow(ALREADY_IN_ORG);
    const active = await owner.membership.findMany({ where: { userId: user.userId, disabledAt: null } });
    expect(active).toHaveLength(1);
    expect(active[0]).toMatchObject({ orgId: org.id, viaSignup: false, role: 'auditor' });
  });

  it('create-org before email-match returns the signup org and leaves the invite pending', async () => {
    const user = await freshUser('seq-create-mail');
    const { org, inviter } = await invitingOrg();
    await inviteFor(org.id, inviter.id, user.email);
    const created = await serviceA.createOrgForSubject(user.sub, 'First', uniqueSlug('seq-cm'));
    orgIds.push(created.id);
    const resolved = await serviceB.resolveActiveMemberships({
      sub: user.sub,
      email: user.email,
      emailVerified: true,
    });
    expect(resolved.memberships).toEqual([{ orgId: created.id, role: 'owner' }]);
    const pending = await owner.membershipInvite.findFirst({ where: { email: user.email, orgId: org.id } });
    expect(pending?.acceptedAt).toBeNull();
  });

  it('email-match before create-org keeps the invited org', async () => {
    const user = await freshUser('seq-mail-create');
    const { org, inviter } = await invitingOrg();
    await inviteFor(org.id, inviter.id, user.email, 'developer');
    const resolved = await serviceA.resolveActiveMemberships({
      sub: user.sub,
      email: user.email,
      emailVerified: true,
    });
    expect(resolved.memberships).toEqual([{ orgId: org.id, role: 'developer' }]);
    await expect(
      serviceB.createOrgForSubject(user.sub, 'Late', uniqueSlug('seq-mc')),
    ).rejects.toBeInstanceOf(ConflictException);
    const active = await owner.membership.findMany({ where: { userId: user.userId, disabledAt: null } });
    expect(active).toHaveLength(1);
    expect(active[0]).toMatchObject({ orgId: org.id, viaSignup: false });
  });

  it('create-org racing email-match / token accept leaves one active membership', async () => {
    for (let round = 0; round < 10; round += 1) {
      const user = await freshUser(`race-token-${round}`);
      const { org, inviter } = await invitingOrg();
      const invite = await inviteFor(org.id, inviter.id, user.email);
      const results = await Promise.allSettled([
        serviceA.createOrgForSubject(user.sub, 'Race', uniqueSlug(`race-t-${round}`)),
        serviceB.acceptInviteByToken(user.sub, invite.token),
      ]);
      for (const result of results) {
        if (result.status === 'rejected') {
          expect(result.reason).toBeInstanceOf(HttpException);
          expect((result.reason as HttpException).getStatus()).toBeLessThan(500);
        }
      }
      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      const active = await owner.membership.findMany({
        where: { userId: user.userId, disabledAt: null },
      });
      expect(active).toHaveLength(1);
      if (results[0].status === 'fulfilled') orgIds.push(results[0].value.id);
    }

    for (let round = 0; round < 10; round += 1) {
      const user = await freshUser(`race-mail-${round}`);
      const { org, inviter } = await invitingOrg();
      await inviteFor(org.id, inviter.id, user.email);
      const results = await Promise.allSettled([
        serviceA.createOrgForSubject(user.sub, 'Race', uniqueSlug(`race-m-${round}`)),
        serviceB.resolveActiveMemberships({
          sub: user.sub,
          email: user.email,
          emailVerified: true,
        }),
      ]);
      for (const result of results) {
        if (result.status === 'rejected') {
          expect(result.reason).toBeInstanceOf(HttpException);
          expect((result.reason as HttpException).getStatus()).toBeLessThan(500);
        }
      }
      const active = await owner.membership.findMany({
        where: { userId: user.userId, disabledAt: null },
      });
      expect(active).toHaveLength(1);
      if (results[0].status === 'fulfilled') orgIds.push(results[0].value.id);
    }
  }, 60_000);

  it('resolveJwt with org_id never accepts an invite', async () => {
    const user = await freshUser('jwt-nope');
    const { org, inviter } = await invitingOrg();
    await inviteFor(org.id, inviter.id, user.email);
    await expect(
      serviceA.resolveJwt({ sub: user.sub, orgId: org.id, email: user.email }),
    ).rejects.toBeInstanceOf(ForbiddenException);
    const pending = await owner.membershipInvite.findFirst({ where: { email: user.email, orgId: org.id } });
    expect(pending?.acceptedAt).toBeNull();
    expect(
      await owner.membership.findUnique({
        where: { orgId_userId: { orgId: org.id, userId: user.userId } },
      }),
    ).toBeNull();
  });

  it('P2002 shapes: owner target is one-active and a ctem_app null target re-checks per path', async () => {
    const orgA = await createOrg(owner);
    const orgB = await createOrg(owner);
    orgIds.push(orgA.id, orgB.id);
    const email = `${uniqueSlug('p2002')}@test.local`;
    const user = await owner.user.create({
      data: { email, name: 'P2002', idpSubject: `test|${email}` },
    });
    userIds.push(user.id);
    await owner.membership.create({
      data: { orgId: orgA.id, userId: user.id, role: 'owner', viaSignup: true },
    });

    let ownerViolation: unknown;
    try {
      await owner.membership.create({
        data: { orgId: orgB.id, userId: user.id, role: 'developer', viaSignup: false },
      });
    } catch (err) {
      ownerViolation = err;
    }
    expect(ownerViolation).toMatchObject({ code: 'P2002' });
    const ownerMeta = (ownerViolation as { meta?: { target?: unknown } }).meta;
    expect(ownerMeta?.target).toEqual(['userId']);
    expect(classifyMembershipUniqueViolation(ownerViolation)).toBe('one-active');
    expect((await resolveCreateOrgUniqueViolation(ownerViolation, async () => false))?.message).toBe(
      ALREADY_IN_ORG,
    );
    const acceptExplicit = await resolveMembershipUniqueViolation(
      ownerViolation,
      async () => false,
      () => inviteAlreadyInOrg(),
      { mapSlug: false },
    );
    expect(problem(acceptExplicit).body.type).toBe(INVITE_ALREADY);

    const app = appClient();
    try {
      let appViolation: unknown;
      try {
        await withOrg(app, orgB.id, (tx) =>
          tx.membership.create({
            data: { orgId: orgB.id, userId: user.id, role: 'developer', viaSignup: false },
          }),
        );
      } catch (err) {
        appViolation = err;
      }
      expect(appViolation).toMatchObject({ code: 'P2002' });
      expect((appViolation as { meta?: { target?: unknown } }).meta?.target).toBeNull();
      expect(classifyMembershipUniqueViolation(appViolation)).toBe('recheck');

      const readActive = async () => {
        const row = await owner.membership.findFirst({
          where: { userId: user.id, disabledAt: null },
          select: { userId: true },
        });
        return row !== null;
      };
      expect((await resolveCreateOrgUniqueViolation(appViolation, readActive))?.message).toBe(
        ALREADY_IN_ORG,
      );
      const acceptRecheck = await resolveMembershipUniqueViolation(
        appViolation,
        readActive,
        () => inviteAlreadyInOrg(),
        { mapSlug: false },
      );
      expect(problem(acceptRecheck).body.type).toBe(INVITE_ALREADY);
      expect((await resolveCreateOrgUniqueViolation(appViolation, async () => false))?.message).toBe(
        'Conflict',
      );
      expect(
        (
          await resolveMembershipUniqueViolation(appViolation, async () => false, () => inviteAlreadyInOrg(), {
            mapSlug: false,
          })
        )?.message,
      ).toBe('Conflict');
    } finally {
      await app.$disconnect();
    }
  });
});

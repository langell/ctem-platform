import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ConflictException } from '@nestjs/common';
import { CreateOrgResponse, ROLE_PERMISSIONS, type Principal, type Role } from '@ctem/contracts';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import {
  createOrg,
  createUserWithMembership,
  deleteOrgCascade,
  ownerClient,
  uniqueSlug,
} from '@ctem/testing';
import { mapCreateOrgUniqueViolation, OrgService } from './org.service';

/**
 * Observed Prisma 6.19.3 P2002 `meta` for partial unique index
 * `memberships_userId_signup_active_key`. The engine does not put the index
 * name in `meta`; `modelName` + `target: ['userId']` is `memberships.userId`.
 * Message text is `Unique constraint failed on the fields: (\`userId\`)`.
 */
const PRISMA_619_SIGNUP_INDEX_META = {
  modelName: 'Membership',
  target: ['userId'],
} as const;

const ALREADY_IN_ORG = 'User already belongs to an organization';
const SLUG_TAKEN = 'Organization slug is already taken';
const NOISE = /prisma:error|Unique constraint|P2002/;
const PINO_LEVELS: Record<string, number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
  fatal: 60,
};

function actor(orgId: string, userId: string, role: Role): Principal {
  return {
    userId,
    orgId,
    role,
    permissions: ROLE_PERMISSIONS[role],
    serviceAccount: null,
    traceId: 'org-create-race',
  };
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

function chunkText(chunk: unknown): string {
  if (typeof chunk === 'string') return chunk;
  if (Buffer.isBuffer(chunk)) return chunk.toString('utf8');
  return String(chunk);
}

interface CapturedLogs {
  pino: string[];
  stdout: string[];
  stderr: string[];
  text(): string;
  restore(): void;
}

function captureLogs(): CapturedLogs {
  const pino: string[] = [];
  const stdout: string[] = [];
  const stderr: string[] = [];
  const consoleLines: string[] = [];
  const stream = pinoStream(rootLogger);
  const origPino = stream.write.bind(stream);
  stream.write = (chunk: string) => {
    pino.push(chunkText(chunk));
    return origPino(chunk);
  };
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((chunk: unknown, ...args: unknown[]) => {
    stdout.push(chunkText(chunk));
    return origOut(chunk as never, ...(args as never[]));
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: unknown, ...args: unknown[]) => {
    stderr.push(chunkText(chunk));
    return origErr(chunk as never, ...(args as never[]));
  }) as typeof process.stderr.write;
  // Prisma 6.19 prints `prisma:error` through console. Vitest's console spy
  // records the call and does not forward it to stdout.write / stderr.write.
  /* eslint-disable no-console */
  const origConsoleLog = console.log.bind(console);
  const origConsoleError = console.error.bind(console);
  console.log = (...args: unknown[]) => {
    consoleLines.push(args.map((arg) => chunkText(arg)).join(' '));
    origConsoleLog(...args);
  };
  console.error = (...args: unknown[]) => {
    consoleLines.push(args.map((arg) => chunkText(arg)).join(' '));
    origConsoleError(...args);
  };
  /* eslint-enable no-console */
  return {
    pino,
    stdout,
    stderr,
    text: () => [...pino, ...stdout, ...stderr, ...consoleLines].join('\n'),
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

function pinoNumericLevel(line: string): number | undefined {
  const start = line.indexOf('{');
  if (start < 0) return undefined;
  try {
    const parsed = JSON.parse(line.slice(start)) as { level?: unknown };
    if (typeof parsed.level === 'number') return parsed.level;
    if (typeof parsed.level === 'string' && parsed.level in PINO_LEVELS) {
      return PINO_LEVELS[parsed.level];
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function crossTenantWarns(lines: string[]): number {
  return lines.filter((line) => line.includes('cross-tenant database access')).length;
}

type CreateResult = PromiseSettledResult<Awaited<ReturnType<OrgService['createOrgForSubject']>>>;

function classifyCreates(results: CreateResult[]) {
  const created: Array<Awaited<ReturnType<OrgService['createOrgForSubject']>>> = [];
  let slugRejections = 0;
  let membershipRejections = 0;
  for (const result of results) {
    if (result.status === 'fulfilled') {
      expect(CreateOrgResponse.safeParse(result.value).success).toBe(true);
      created.push(result.value);
      continue;
    }
    expect(result.reason).toBeInstanceOf(ConflictException);
    const message = (result.reason as ConflictException).message;
    if (message === SLUG_TAKEN) {
      slugRejections += 1;
      continue;
    }
    expect(message).toBe(ALREADY_IN_ORG);
    membershipRejections += 1;
  }
  return { created, slugRejections, membershipRejections };
}

describe('org create race', () => {
  let owner: PrismaClient;
  let prismaA: PrismaService;
  let prismaB: PrismaService;
  let serviceA: OrgService;
  let serviceB: OrgService;

  beforeAll(async () => {
    owner = ownerClient();
    prismaA = new PrismaService();
    prismaB = new PrismaService();
    serviceA = new OrgService(prismaA);
    serviceB = new OrgService(prismaB);
  });

  afterAll(async () => {
    await serviceA.onModuleDestroy();
    await serviceB.onModuleDestroy();
    await Promise.all([owner.$disconnect(), prismaA.$disconnect(), prismaB.$disconnect()]);
  });

  async function freshSubject(label: string) {
    const sub = `idp|${uniqueSlug(label)}`;
    const email = `${uniqueSlug(label)}@test.local`;
    const user = await serviceA.resolveActiveMemberships({ sub, email, name: 'Race Owner' });
    return { sub, email, userId: user.userId };
  }

  async function deleteUserOrgs(userId: string) {
    const rows = await owner.membership.findMany({
      where: { userId },
      select: { orgId: true },
    });
    const orgIds = [...new Set(rows.map((row) => row.orgId))];
    for (const orgId of orgIds) {
      await deleteOrgCascade(owner, orgId);
    }
    await owner.user.deleteMany({ where: { id: userId } });
  }

  async function createWave(calls: Array<() => ReturnType<OrgService['createOrgForSubject']>>) {
    return Promise.allSettled(calls.map((call) => call()));
  }

  it('concurrent creates for one subject leave one org and one owner membership', async () => {
    const subject = await freshSubject('race');
    try {
      const first = await createWave([
        () => serviceA.createOrgForSubject(subject.sub, 'Race A', uniqueSlug('race-a')),
        () => serviceB.createOrgForSubject(subject.sub, 'Race B', uniqueSlug('race-b')),
      ]);
      const mixed = await createWave([
        () => serviceA.createOrgForSubject(subject.sub, 'Race C', uniqueSlug('race-c')),
        () => serviceB.createOrgForSubject(subject.sub, 'Race D', uniqueSlug('race-d')),
        () => serviceA.createOrgForSubject(subject.sub, 'Race E', uniqueSlug('race-e')),
        () => serviceB.createOrgForSubject(subject.sub, 'Race F', uniqueSlug('race-f')),
        () => serviceA.createOrgForSubject(subject.sub, 'Race G', uniqueSlug('race-g')),
      ]);
      const { created, slugRejections, membershipRejections } = classifyCreates([
        ...first,
        ...mixed,
      ]);
      // A slug collision is not evidence of the membership rule, so it is not counted.
      expect(slugRejections).toBe(0);
      expect(created).toHaveLength(1);
      expect(membershipRejections).toBe(6);

      const memberships = await owner.membership.findMany({ where: { userId: subject.userId } });
      expect(memberships).toHaveLength(1);
      expect(memberships[0]).toMatchObject({
        role: 'owner',
        viaSignup: true,
        disabledAt: null,
        orgId: created[0]!.id,
      });
      const orgs = await owner.organization.count({
        where: { memberships: { some: { userId: subject.userId } } },
      });
      expect(orgs).toBe(1);
    } finally {
      await deleteUserOrgs(subject.userId);
    }
  });

  it('backstop index rejects a second active signup membership without the lock', async () => {
    const orgA = await createOrg(owner);
    const orgB = await createOrg(owner);
    const orgC = await createOrg(owner);
    const email = `${uniqueSlug('backstop')}@test.local`;
    const user = await owner.user.create({
      data: { email, name: 'Backstop', idpSubject: `test|${email}` },
    });
    const setup = new PrismaService();
    const violator = new PrismaService();
    try {
      await setup.withOrg(orgA.id, (tx) =>
        tx.membership.create({
          data: { orgId: orgA.id, userId: user.id, role: 'owner', viaSignup: true },
        }),
      );

      const captured = captureLogs();
      let violation: unknown;
      try {
        await violator.withOrg(orgB.id, (tx) =>
          tx.membership.create({
            data: { orgId: orgB.id, userId: user.id, role: 'developer', viaSignup: true },
          }),
        );
      } catch (err) {
        violation = err;
      } finally {
        captured.restore();
      }

      expect(violation).toMatchObject({ code: 'P2002' });
      const meta = (violation as { meta?: unknown }).meta;
      expect(meta, `observed P2002 meta: ${JSON.stringify(meta)}`).toEqual(
        PRISMA_619_SIGNUP_INDEX_META,
      );
      expect(mapCreateOrgUniqueViolation(violation)?.message).toBe(ALREADY_IN_ORG);
      expect(captured.text()).toMatch(/prisma:error/);
      expect(captured.text()).toMatch(NOISE);

      const invited = await setup.withOrg(orgB.id, (tx) =>
        tx.membership.create({
          data: { orgId: orgB.id, userId: user.id, role: 'developer', viaSignup: false },
        }),
      );
      expect(invited.viaSignup).toBe(false);

      await owner.membership.update({
        where: { orgId_userId: { orgId: orgA.id, userId: user.id } },
        data: { disabledAt: new Date() },
      });
      const replacement = await setup.withOrg(orgC.id, (tx) =>
        tx.membership.create({
          data: { orgId: orgC.id, userId: user.id, role: 'owner', viaSignup: true },
        }),
      );
      expect(replacement.viaSignup).toBe(true);
      expect(replacement.orgId).toBe(orgC.id);
    } finally {
      await setup.$disconnect();
      await violator.$disconnect();
      await deleteOrgCascade(owner, orgA.id, [user.id]);
      await deleteOrgCascade(owner, orgB.id);
      await deleteOrgCascade(owner, orgC.id);
    }
  });

  it('losing request logs no prisma:error or unique violation', async () => {
    const subject = await freshSubject('quiet');
    const calls = [
      () => serviceA.createOrgForSubject(subject.sub, 'Quiet A', uniqueSlug('quiet-a')),
      () => serviceB.createOrgForSubject(subject.sub, 'Quiet B', uniqueSlug('quiet-b')),
      () => serviceA.createOrgForSubject(subject.sub, 'Quiet C', uniqueSlug('quiet-c')),
      () => serviceB.createOrgForSubject(subject.sub, 'Quiet D', uniqueSlug('quiet-d')),
      () => serviceA.createOrgForSubject(subject.sub, 'Quiet E', uniqueSlug('quiet-e')),
      () => serviceB.createOrgForSubject(subject.sub, 'Quiet F', uniqueSlug('quiet-f')),
      () => serviceA.createOrgForSubject(subject.sub, 'Quiet G', uniqueSlug('quiet-g')),
    ];
    const captured = captureLogs();
    try {
      const first = await Promise.allSettled(calls.slice(0, 2).map((call) => call()));
      const mixed = await Promise.allSettled(calls.slice(2).map((call) => call()));
      const { created, slugRejections, membershipRejections } = classifyCreates([
        ...first,
        ...mixed,
      ]);
      expect(slugRejections).toBe(0);
      expect(created).toHaveLength(1);
      expect(membershipRejections).toBe(calls.length - 1);

      expect(captured.text()).not.toMatch(NOISE);
      const levels = captured.pino.map(pinoNumericLevel).filter((level) => level !== undefined);
      expect(levels.filter((level) => level >= 50)).toEqual([]);
      const warns = crossTenantWarns(captured.pino) || crossTenantWarns(captured.stdout);
      expect(warns).toBe(calls.length);
    } finally {
      captured.restore();
      await deleteUserOrgs(subject.userId);
    }
  });

  it('a self-signup owner can accept an invite into a second org', async () => {
    const orgIds: string[] = [];
    const userIds: string[] = [];
    try {
      for (const role of ['developer', 'owner'] as const) {
        const subject = await freshSubject(`invite-${role}`);
        userIds.push(subject.userId);
        const orgA = await serviceA.createOrgForSubject(
          subject.sub,
          `Signup ${role}`,
          uniqueSlug(`inv-${role}`),
        );
        orgIds.push(orgA.id);

        const orgB = await createOrg(owner);
        orgIds.push(orgB.id);
        const inviter = await createUserWithMembership(owner, orgB.id, 'owner');
        userIds.push(inviter.id);
        await serviceB.invite(orgB.id, actor(orgB.id, inviter.id, 'owner'), {
          email: subject.email,
          role,
        });

        const resolved = await serviceB.resolveJwt({
          sub: subject.sub,
          orgId: orgB.id,
          email: subject.email,
        });
        expect(resolved.role).toBe(role);
        expect(resolved.userId).toBe(subject.userId);

        const active = await owner.membership.findMany({
          where: { userId: subject.userId, disabledAt: null },
          orderBy: { createdAt: 'asc' },
        });
        expect(active).toHaveLength(2);
        const signup = active.find((row) => row.orgId === orgA.id);
        const invited = active.find((row) => row.orgId === orgB.id);
        expect(signup).toMatchObject({ role: 'owner', viaSignup: true });
        expect(invited).toMatchObject({ role, viaSignup: false });
      }
    } finally {
      for (const orgId of orgIds) await deleteOrgCascade(owner, orgId);
      if (userIds.length) await owner.user.deleteMany({ where: { id: { in: userIds } } });
    }
  });
});

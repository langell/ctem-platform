import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ownerClient, uniqueSlug } from '@ctem/testing';

const MIGRATION = resolve(
  'libs/db/prisma/migrations/20261007124500_membership_one_active/migration.sql',
);

class RolledBack extends Error {}

function extracted(sql: string) {
  const begin = sql.indexOf('-- guard:begin');
  const end = sql.indexOf('-- guard:end');
  const drop = sql.indexOf('DROP INDEX IF EXISTS "memberships_userId_signup_active_key"');
  const createAt = sql.indexOf('CREATE UNIQUE INDEX "memberships_userId_active_key"');
  const emailAt = sql.indexOf('CREATE INDEX "membership_invites_email_pending_idx"');
  expect(begin, 'guard starts the migration').toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(begin);
  expect(drop).toBeGreaterThan(end);
  expect(createAt).toBeGreaterThan(drop);
  expect(emailAt).toBeGreaterThan(createAt);
  const guard = sql.slice(begin + '-- guard:begin'.length, end).trim();
  const createSql = sql
    .slice(createAt)
    .match(/CREATE UNIQUE INDEX "memberships_userId_active_key"[\s\S]*?;/)?.[0];
  expect(guard.startsWith('DO $$')).toBe(true);
  expect(createSql).toBeTruthy();
  return { guard, createSql: createSql! };
}

describe('membership one-active migration guard', () => {
  it('raises while two memberships are active, then creates the index after one is disabled', async () => {
    const sql = readFileSync(MIGRATION, 'utf8');
    const { guard, createSql } = extracted(sql);
    const owner = ownerClient();
    try {
      await owner.$transaction(async (tx) => {
        await tx.$executeRawUnsafe('DROP INDEX "memberships_userId_active_key"');
        const slugA = uniqueSlug('guard-a');
        const slugB = uniqueSlug('guard-b');
        const orgA = await tx.organization.create({ data: { name: slugA, slug: slugA } });
        const orgB = await tx.organization.create({ data: { name: slugB, slug: slugB } });
        const email = `${uniqueSlug('guard')}@test.local`;
        const user = await tx.user.create({
          data: { email, name: 'Guard', idpSubject: `test|${email}` },
        });
        await tx.membership.create({
          data: { orgId: orgA.id, userId: user.id, role: 'owner', viaSignup: false },
        });
        await tx.membership.create({
          data: { orgId: orgB.id, userId: user.id, role: 'developer', viaSignup: false },
        });

        await tx.$executeRawUnsafe('SAVEPOINT ctem_one_active_guard');
        let guardError: unknown;
        try {
          await tx.$executeRawUnsafe(guard);
        } catch (err) {
          guardError = err;
        }
        expect(String(guardError)).toMatch(/1 user\(s\) have 2\+ active memberships/);
        await tx.$executeRawUnsafe('ROLLBACK TO SAVEPOINT ctem_one_active_guard');

        await tx.membership.update({
          where: { orgId_userId: { orgId: orgB.id, userId: user.id } },
          data: { disabledAt: new Date() },
        });
        await tx.$executeRawUnsafe(guard);
        await tx.$executeRawUnsafe(createSql);
        const indexes = await tx.$queryRaw<Array<{ indexname: string }>>`
          SELECT indexname FROM pg_indexes
          WHERE schemaname = 'public' AND indexname = 'memberships_userId_active_key'
        `;
        expect(indexes).toHaveLength(1);
        throw new RolledBack();
      });
      throw new Error('one-active guard transaction committed');
    } catch (err) {
      if (!(err instanceof RolledBack)) throw err;
    } finally {
      await owner.$disconnect();
    }
  });
});

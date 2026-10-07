import { ConflictException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import {
  SIGNUP_MEMBERSHIP_INDEX,
  mapCreateOrgUniqueViolation,
  resolveCreateOrgUniqueViolation,
} from './org.service';

const SLUG_TAKEN = 'Organization slug is already taken';
const ALREADY_IN_ORG = 'User already belongs to an organization';

function p2002(meta: Record<string, unknown>) {
  return { code: 'P2002', meta };
}

function immediate(err: unknown): ConflictException | null {
  const mapped = mapCreateOrgUniqueViolation(err);
  if (!mapped) return null;
  expect(mapped.action).toBe('conflict');
  return mapped.action === 'conflict' ? mapped.exception : null;
}

function expectConflict(err: ConflictException | null, message: string) {
  expect(err).toBeInstanceOf(ConflictException);
  expect(err?.getStatus()).toBe(409);
  expect(err?.message).toBe(message);
  const body = err?.getResponse() as { title?: string; message?: string };
  expect(body.title ?? err?.message).toBe(message);
}

describe('mapCreateOrgUniqueViolation', () => {
  it('maps a slug target to the slug 409', () => {
    expectConflict(immediate(p2002({ target: ['slug'] })), SLUG_TAKEN);
    expectConflict(
      immediate(p2002({ modelName: 'Organization', target: 'organizations_slug_key' })),
      SLUG_TAKEN,
    );
  });

  it('maps the signup index, including a memberships.userId target, to the membership 409', () => {
    expectConflict(immediate(p2002({ target: SIGNUP_MEMBERSHIP_INDEX })), ALREADY_IN_ORG);
    expectConflict(
      immediate(
        p2002({ modelName: 'Membership', target: ['userId'], constraint: SIGNUP_MEMBERSHIP_INDEX }),
      ),
      ALREADY_IN_ORG,
    );
    expectConflict(
      immediate(p2002({ modelName: 'Membership', target: ['userId'] })),
      ALREADY_IN_ORG,
    );
    expectConflict(
      immediate(
        p2002({ modelName: 'Membership', target: null, constraint: SIGNUP_MEMBERSHIP_INDEX }),
      ),
      ALREADY_IN_ORG,
    );
    expectConflict(immediate(p2002({ target: 'memberships.userId' })), ALREADY_IN_ORG);
  });

  it('re-checks a null or unresolvable Membership target against an active viaSignup row', async () => {
    for (const meta of [
      { modelName: 'Membership', target: null },
      { modelName: 'Membership' },
      { modelName: 'Membership', target: [] },
    ]) {
      expect(mapCreateOrgUniqueViolation(p2002(meta))).toEqual({
        action: 'recheck-active-signup',
      });
    }

    const active = vi.fn(async () => true);
    expectConflict(
      await resolveCreateOrgUniqueViolation(
        p2002({ modelName: 'Membership', target: null }),
        active,
      ),
      ALREADY_IN_ORG,
    );
    expect(active).toHaveBeenCalledTimes(1);

    const absent = vi.fn(async () => false);
    expectConflict(
      await resolveCreateOrgUniqueViolation(
        p2002({ modelName: 'Membership', target: null }),
        absent,
      ),
      'Conflict',
    );
    expect(absent).toHaveBeenCalledTimes(1);

    const unused = vi.fn(async () => false);
    expectConflict(
      await resolveCreateOrgUniqueViolation(
        p2002({ modelName: 'Membership', target: ['userId'] }),
        unused,
      ),
      ALREADY_IN_ORG,
    );
    expect(unused).not.toHaveBeenCalled();
  });

  it('maps any other P2002 to a generic Conflict and never the membership message', async () => {
    expectConflict(immediate(p2002({ modelName: 'User', target: ['email'] })), 'Conflict');
    expectConflict(
      immediate(p2002({ modelName: 'Membership', target: ['orgId', 'userId'] })),
      'Conflict',
    );
    expectConflict(immediate(p2002({})), 'Conflict');
    expectConflict(immediate(p2002({ modelName: 'Organization', target: null })), 'Conflict');
    expectConflict(immediate(p2002({ modelName: 'User', target: null })), 'Conflict');
    expect(mapCreateOrgUniqueViolation({ code: 'P2003', meta: { target: ['userId'] } })).toBeNull();

    const unused = vi.fn(async () => true);
    expectConflict(
      await resolveCreateOrgUniqueViolation(
        p2002({ modelName: 'Organization', target: null }),
        unused,
      ),
      'Conflict',
    );
    expect(unused).not.toHaveBeenCalled();
  });
});

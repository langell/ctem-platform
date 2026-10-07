import { ConflictException, HttpException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import {
  ACTIVE_MEMBERSHIP_INDEX,
  classifyMembershipUniqueViolation,
  inviteAlreadyInOrg,
  mapCreateOrgUniqueViolation,
  resolveCreateOrgUniqueViolation,
  resolveMembershipUniqueViolation,
} from './org.service';

const SLUG_TAKEN = 'Organization slug is already taken';
const ALREADY_IN_ORG = 'User already belongs to an organization';

function p2002(meta: Record<string, unknown>) {
  return { code: 'P2002', meta };
}

function expectConflict(err: HttpException | null, message: string) {
  expect(err).toBeInstanceOf(ConflictException);
  expect(err?.getStatus()).toBe(409);
  expect(err?.message).toBe(message);
}

function expectInviteAlready(err: HttpException | null) {
  expect(err).toBeInstanceOf(HttpException);
  expect(err?.getStatus()).toBe(409);
  const body = err?.getResponse() as { type?: string; title?: string; detail?: string };
  expect(body.type).toBe('urn:ctem:problem:invite-already-in-org');
  expect(body.title).toBe('You already belong to an organization');
  expect(body.detail).toBe(
    'Ask an admin of your current organization to remove you, then open this invite again.',
  );
}

describe('classifyMembershipUniqueViolation', () => {
  it('maps a slug target to slug', () => {
    expect(classifyMembershipUniqueViolation(p2002({ target: ['slug'] }))).toBe('slug');
    expect(
      classifyMembershipUniqueViolation(
        p2002({ modelName: 'Organization', target: 'organizations_slug_key' }),
      ),
    ).toBe('slug');
  });

  it('maps Membership userId and the one-active index name to one-active', () => {
    expect(
      classifyMembershipUniqueViolation(p2002({ modelName: 'Membership', target: ['userId'] })),
    ).toBe('one-active');
    expect(
      classifyMembershipUniqueViolation(
        p2002({
          modelName: 'Membership',
          target: ['userId'],
          constraint: ACTIVE_MEMBERSHIP_INDEX,
        }),
      ),
    ).toBe('one-active');
    expect(classifyMembershipUniqueViolation(p2002({ target: ACTIVE_MEMBERSHIP_INDEX }))).toBe(
      'one-active',
    );
    expect(
      classifyMembershipUniqueViolation(
        p2002({ modelName: 'Membership', target: null, constraint: ACTIVE_MEMBERSHIP_INDEX }),
      ),
    ).toBe('one-active');
  });

  it('rechecks a null, empty, or missing Membership target', () => {
    for (const meta of [
      { modelName: 'Membership', target: null },
      { modelName: 'Membership' },
      { modelName: 'Membership', target: [] },
    ]) {
      expect(classifyMembershipUniqueViolation(p2002(meta))).toBe('recheck');
      expect(mapCreateOrgUniqueViolation(p2002(meta))).toEqual({ action: 'recheck' });
    }
  });

  it('maps the PK, a tokenHash collision, and other models to conflict', () => {
    expect(
      classifyMembershipUniqueViolation(
        p2002({ modelName: 'Membership', target: ['orgId', 'userId'] }),
      ),
    ).toBe('conflict');
    expect(
      classifyMembershipUniqueViolation(
        p2002({ modelName: 'MembershipInvite', target: ['tokenHash'] }),
      ),
    ).toBe('conflict');
    expect(classifyMembershipUniqueViolation(p2002({}))).toBe('conflict');
    expect(
      classifyMembershipUniqueViolation(p2002({ modelName: 'Organization', target: null })),
    ).toBe('conflict');
    expect(classifyMembershipUniqueViolation(p2002({ modelName: 'User', target: null }))).toBe(
      'conflict',
    );
    expect(classifyMembershipUniqueViolation({ code: 'P2003', meta: { target: ['userId'] } })).toBe(
      null,
    );
  });
});

describe('path message selection', () => {
  const oneActive = p2002({ modelName: 'Membership', target: ['userId'] });
  const nullTarget = p2002({ modelName: 'Membership', target: null });

  it('create-org uses the signup message and accept uses invite-already-in-org for the same violation', async () => {
    expectConflict(
      await resolveMembershipUniqueViolation(oneActive, async () => false, () =>
        new ConflictException(ALREADY_IN_ORG),
      ),
      ALREADY_IN_ORG,
    );
    expectInviteAlready(
      await resolveMembershipUniqueViolation(
        oneActive,
        async () => false,
        () => inviteAlreadyInOrg(),
        { mapSlug: false },
      ),
    );

    const unused = vi.fn(async () => true);
    expectConflict(await resolveCreateOrgUniqueViolation(oneActive, unused), ALREADY_IN_ORG);
    expect(unused).not.toHaveBeenCalled();
  });

  it('recheck true uses the path message and recheck false is a generic Conflict', async () => {
    const createTrue = vi.fn(async () => true);
    expectConflict(await resolveCreateOrgUniqueViolation(nullTarget, createTrue), ALREADY_IN_ORG);
    expect(createTrue).toHaveBeenCalledTimes(1);

    const createFalse = vi.fn(async () => false);
    expectConflict(await resolveCreateOrgUniqueViolation(nullTarget, createFalse), 'Conflict');
    expect(createFalse).toHaveBeenCalledTimes(1);

    const acceptTrue = vi.fn(async () => true);
    expectInviteAlready(
      await resolveMembershipUniqueViolation(nullTarget, acceptTrue, () => inviteAlreadyInOrg(), {
        mapSlug: false,
      }),
    );
    expect(acceptTrue).toHaveBeenCalledTimes(1);

    const acceptFalse = vi.fn(async () => false);
    expectConflict(
      await resolveMembershipUniqueViolation(nullTarget, acceptFalse, () => inviteAlreadyInOrg(), {
        mapSlug: false,
      }),
      'Conflict',
    );
    expect(acceptFalse).toHaveBeenCalledTimes(1);
  });

  it('maps slug only for create-org and any other P2002 to a generic Conflict', async () => {
    expectConflict(
      await resolveCreateOrgUniqueViolation(p2002({ target: ['slug'] }), async () => true),
      SLUG_TAKEN,
    );
    expectConflict(
      await resolveMembershipUniqueViolation(
        p2002({ target: ['slug'] }),
        async () => true,
        () => inviteAlreadyInOrg(),
        { mapSlug: false },
      ),
      'Conflict',
    );
    expectConflict(
      await resolveCreateOrgUniqueViolation(
        p2002({ modelName: 'Membership', target: ['orgId', 'userId'] }),
        async () => true,
      ),
      'Conflict',
    );
    const unused = vi.fn(async () => true);
    expectConflict(
      await resolveCreateOrgUniqueViolation(
        p2002({ modelName: 'Organization', target: null }),
        unused,
      ),
      'Conflict',
    );
    expect(unused).not.toHaveBeenCalled();
    expect(mapCreateOrgUniqueViolation(p2002({ target: ['slug'] }))?.action).toBe('conflict');
  });
});

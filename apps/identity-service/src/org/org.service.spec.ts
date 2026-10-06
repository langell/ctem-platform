import { ConflictException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { SIGNUP_MEMBERSHIP_INDEX, mapCreateOrgUniqueViolation } from './org.service';

const SLUG_TAKEN = 'Organization slug is already taken';
const ALREADY_IN_ORG = 'User already belongs to an organization';

function p2002(meta: Record<string, unknown>) {
  return { code: 'P2002', meta };
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
    expectConflict(mapCreateOrgUniqueViolation(p2002({ target: ['slug'] })), SLUG_TAKEN);
    expectConflict(
      mapCreateOrgUniqueViolation(
        p2002({ modelName: 'Organization', target: 'organizations_slug_key' }),
      ),
      SLUG_TAKEN,
    );
  });

  it('maps the signup index, including a memberships.userId target, to the membership 409', () => {
    expectConflict(
      mapCreateOrgUniqueViolation(p2002({ target: SIGNUP_MEMBERSHIP_INDEX })),
      ALREADY_IN_ORG,
    );
    expectConflict(
      mapCreateOrgUniqueViolation(
        p2002({ modelName: 'Membership', target: ['userId'], constraint: SIGNUP_MEMBERSHIP_INDEX }),
      ),
      ALREADY_IN_ORG,
    );
    expectConflict(
      mapCreateOrgUniqueViolation(p2002({ modelName: 'Membership', target: ['userId'] })),
      ALREADY_IN_ORG,
    );
    expectConflict(
      mapCreateOrgUniqueViolation(p2002({ target: 'memberships.userId' })),
      ALREADY_IN_ORG,
    );
  });

  it('maps any other P2002 to a generic Conflict and never the membership message', () => {
    expectConflict(
      mapCreateOrgUniqueViolation(p2002({ modelName: 'User', target: ['email'] })),
      'Conflict',
    );
    expectConflict(
      mapCreateOrgUniqueViolation(p2002({ modelName: 'Membership', target: ['orgId', 'userId'] })),
      'Conflict',
    );
    expectConflict(mapCreateOrgUniqueViolation(p2002({})), 'Conflict');
    expect(mapCreateOrgUniqueViolation({ code: 'P2003', meta: { target: ['userId'] } })).toBeNull();
  });
});

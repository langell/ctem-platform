import { expect, test, type Page } from '@playwright/test';
import { loginAsDemoAnalyst } from './helpers/auth';
import { createKeycloakUser } from './helpers/keycloak-admin';
import { registerFreshOwnerOnCreateOrg, submitFreshOwnerOrg } from './helpers/signup';
import { decodeJwtPayload, DEMO_ORG_ID, readSessionToken } from './helpers/session';

async function inviteByAnalyst(page: Page, token: string, email: string) {
  return page.evaluate(
    async ({ accessToken, inviteEmail }) => {
      const res = await fetch('/v1/org/members', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${accessToken}`,
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: JSON.stringify({ email: inviteEmail, role: 'developer' }),
      });
      return { status: res.status, body: (await res.json()) as { token?: string } };
    },
    { accessToken: token, inviteEmail: email },
  );
}

async function loginWithPassword(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/login');
  await page.getByRole('button', { name: 'Sign in with Keycloak' }).click();
  await expect(page.locator('#username')).toBeVisible({ timeout: 30_000 });
  await page.locator('#username').fill(email);
  await page.locator('#password').fill(password);
  await page.locator('#kc-login').click();
}

async function sessionFor(page: Page, token: string) {
  return page.evaluate(async (accessToken) => {
    const res = await fetch('/v1/session', {
      headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' },
    });
    return {
      status: res.status,
      body: (await res.json()) as { orgId?: string; role?: string; title?: string },
    };
  }, token);
}

test.describe('invite accept on sign-in', () => {
  test.describe.configure({ timeout: 120_000 });

  test('verified invitee signs in and lands in the inviting org', async ({ page, browser }) => {
    const analystJwt = await loginAsDemoAnalyst(page);
    const email = `verified-${Date.now().toString(36)}@invite.test`;
    const password = `Invite-pass-${Date.now().toString(36)}`;
    const invited = await inviteByAnalyst(page, analystJwt, email);
    expect(invited.status).toBe(201);
    expect(invited.body.token).toMatch(/^ctem_inv_/);
    await createKeycloakUser({ email, verified: true, password });

    const inviteeContext = await browser.newContext();
    const invitee = await inviteeContext.newPage();
    const paths: string[] = [];
    invitee.on('framenavigated', (frame) => {
      if (frame === invitee.mainFrame()) paths.push(new URL(frame.url()).pathname);
    });
    try {
      await loginWithPassword(invitee, email, password);
      await invitee.waitForURL(/\/findings/, { timeout: 30_000 });
      await expect(invitee.getByRole('heading', { name: 'Findings' })).toBeVisible();
      expect(paths).not.toContain('/create-org');
      const token = await readSessionToken(invitee);
      if (!token) throw new Error('invitee session token missing');
      const claims = decodeJwtPayload(token);
      expect(claims.email_verified).toBe(true);
      expect(claims.org_id).toBeUndefined();
      const session = await sessionFor(invitee, token);
      expect(session.status).toBe(200);
      expect(session.body.orgId).toBe(DEMO_ORG_ID);
      expect(session.body.role).toBe('developer');
    } finally {
      await inviteeContext.close();
    }
  });

  test('unverified invitee lands on create-org and does not join', async ({ page, browser }) => {
    const analystJwt = await loginAsDemoAnalyst(page);
    const email = `unverified-${Date.now().toString(36)}@invite.test`;
    const password = `Invite-pass-${Date.now().toString(36)}`;
    const invited = await inviteByAnalyst(page, analystJwt, email);
    expect(invited.status).toBe(201);
    await createKeycloakUser({ email, verified: false, password });

    const inviteeContext = await browser.newContext();
    const invitee = await inviteeContext.newPage();
    try {
      await loginWithPassword(invitee, email, password);
      await invitee.waitForURL(/\/create-org/, { timeout: 30_000 });
      await expect(invitee.getByText('Create your organization')).toBeVisible();
      const token = await readSessionToken(invitee);
      if (!token) throw new Error('unverified invitee session token missing');
      const claims = decodeJwtPayload(token);
      expect(claims.org_id).toBeUndefined();
      const session = await sessionFor(invitee, token);
      expect(session.status).toBe(403);
      expect(session.body.title).toBe('No organization');
    } finally {
      await inviteeContext.close();
    }
  });

  test('org owner stays in their org and token accept returns invite-already-in-org', async ({
    page,
    browser,
  }) => {
    const registered = await registerFreshOwnerOnCreateOrg(page);
    const owner = await submitFreshOwnerOrg(page, registered);

    const analystContext = await browser.newContext();
    const analyst = await analystContext.newPage();
    let inviteToken = '';
    try {
      const analystJwt = await loginAsDemoAnalyst(analyst);
      const invited = await inviteByAnalyst(analyst, analystJwt, registered.email);
      expect(invited.status).toBe(201);
      inviteToken = invited.body.token ?? '';
      expect(inviteToken).toMatch(/^ctem_inv_/);
    } finally {
      await analystContext.close();
    }

    const accept = await page.evaluate(
      async ({ accessToken, token }) => {
        const res = await fetch('/v1/invites/accept', {
          method: 'POST',
          headers: {
            authorization: `Bearer ${accessToken}`,
            'content-type': 'application/json',
            accept: 'application/json',
          },
          body: JSON.stringify({ token }),
        });
        return { status: res.status, body: (await res.json()) as { type?: string; orgId?: string } };
      },
      { accessToken: registered.token, token: inviteToken },
    );
    expect(accept.status).toBe(409);
    expect(accept.body.type).toBe('urn:ctem:problem:invite-already-in-org');

    const session = await sessionFor(page, registered.token);
    expect(session.status).toBe(200);
    expect(session.body.orgId).toBe(owner.orgId);
    expect(session.body.role).toBe('owner');
  });
});

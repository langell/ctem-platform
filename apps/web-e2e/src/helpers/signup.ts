import { expect, type Page } from '@playwright/test';
import { expectCtemLoginHasNoSecretFields, startKeycloakAuthorize } from './auth';
import { decodeJwtPayload, DEMO_ORG_ID, readSessionToken } from './session';

export interface FreshOwner {
  orgId: string;
  orgName: string;
  slug: string;
}

/**
 * #87 signup path: a new IdP user creates one org and lands as owner.
 * Shared by the signup spec and the GitHub connect spec.
 */
export async function signUpFreshOwner(page: Page): Promise<FreshOwner> {
  const stamp = Date.now().toString(36);
  const username = `e2e${stamp}`;
  const email = `${username}@signup.test`;
  const password = `Signup-pass-${stamp}`;
  const orgName = `E2E Org ${stamp}`;
  const slug = `e2e-${stamp}`;

  await page.goto('/login');
  await expectCtemLoginHasNoSecretFields(page);

  const session403 = page.waitForResponse(
    (res) => res.url().includes('/v1/session') && res.request().method() === 'GET',
  );

  await startKeycloakAuthorize(page);
  await page.getByRole('link', { name: 'Register' }).click();
  await expect(page.locator('#username')).toBeVisible({ timeout: 30_000 });
  await page.locator('#username').fill(username);
  await page.locator('#email').fill(email);
  await page.locator('#firstName').fill('E2E');
  await page.locator('#lastName').fill('Owner');
  await page.locator('#password').fill(password);
  await page.locator('#password-confirm').fill(password);
  await page
    .locator('#kc-register-form input[type="submit"], #kc-register-form button[type="submit"]')
    .first()
    .click();

  const denied = await session403;
  expect(denied.status(), 'session before an org exists').toBe(403);
  const deniedBody = (await denied.json()) as { title?: string };
  expect(deniedBody.title).toBe('No organization');

  await page.waitForURL(/\/create-org/, { timeout: 30_000 });
  await expect(page.locator('aside.dock')).toHaveCount(0);
  await expect(page.getByText('Create your organization')).toBeVisible();

  const jwtBefore = await readSessionToken(page);
  if (!jwtBefore) throw new Error('expected a stored access token before create');
  const claimsBefore = decodeJwtPayload(jwtBefore);
  expect(claimsBefore.sub).toBeTruthy();
  expect(claimsBefore.sub).not.toBe('demo|analyst');
  expect(claimsBefore.org_id).toBeUndefined();

  const created = page.waitForResponse(
    (res) => res.url().includes('/v1/orgs') && res.request().method() === 'POST',
  );
  await page.getByLabel('Name').fill(orgName);
  await page.getByLabel('Slug').fill(slug);
  await page.getByRole('button', { name: 'Create organization' }).click();

  const createRes = await created;
  expect(createRes.status()).toBe(201);
  const posted = createRes.request().postDataJSON() as Record<string, unknown>;
  expect(posted).toEqual({ name: orgName, slug });
  expect(posted).not.toHaveProperty('orgId');
  expect(posted).not.toHaveProperty('org_id');
  expect(posted).not.toHaveProperty('role');
  expect(posted).not.toHaveProperty('userId');
  expect(posted).not.toHaveProperty('plan');

  const createdBody = (await createRes.json()) as { id?: string; plan?: string; slug?: string };
  expect(createdBody.plan).toBe('trial');
  expect(createdBody.slug).toBe(slug);
  expect(createdBody.id).toBeTruthy();
  expect(createdBody.id).not.toBe(DEMO_ORG_ID);

  await page.waitForURL(/\/findings/, { timeout: 30_000 });
  await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();
  await expect(page.locator('aside.dock .session span').first()).toHaveText('owner');

  const jwtAfter = await readSessionToken(page);
  expect(jwtAfter).toBe(jwtBefore);
  const session = await page.evaluate(async (token) => {
    const res = await fetch('/v1/session', {
      headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
    });
    return {
      status: res.status,
      body: (await res.json()) as { orgId?: string; role?: string; userId?: string },
    };
  }, jwtAfter);
  expect(session.status).toBe(200);
  expect(session.body.role).toBe('owner');
  expect(session.body.orgId).toBe(createdBody.id);
  expect(session.body.userId).not.toBe(claimsBefore.sub);

  return { orgId: createdBody.id as string, orgName, slug };
}

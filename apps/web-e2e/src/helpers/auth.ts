import { expect, type Page } from '@playwright/test';
import { expectJwtSession, expectStillSignedIn } from './session';

/** Compose Keycloak demo analyst — same credentials as `make demo-token`. */
export const DEMO_USERNAME = process.env.DEMO_USERNAME ?? 'analyst';
export const DEMO_PASSWORD = process.env.DEMO_PASSWORD ?? 'demo';

/**
 * CTEM /login is OIDC redirect only. A password or JWT-paste field here is a
 * regression — Keycloak owns the password prompt after the authorize redirect.
 */
export async function expectCtemLoginHasNoSecretFields(page: Page): Promise<void> {
  await expect(page.getByRole('heading', { name: 'CTEM' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in with Keycloak' })).toHaveCount(1);
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
  await expect(page.locator('textarea')).toHaveCount(0);
  await expect(page.getByPlaceholder(/eyJ/)).toHaveCount(0);
  await expect(page.getByText(/Paste a JWT/i)).toHaveCount(0);
  await expect(page.getByText(/personal access|machine token|ctem_pat_/i)).toHaveCount(0);
}

export async function startKeycloakAuthorize(page: Page): Promise<void> {
  await page.goto('/login');
  await expectCtemLoginHasNoSecretFields(page);
  await page.getByRole('button', { name: 'Sign in with Keycloak' }).click();
  await page.waitForURL(/\/realms\/ctem\/protocol\/openid-connect\/auth/, { timeout: 30_000 });
  const authorize = new URL(page.url());
  expect(
    authorize.searchParams.get('client_id'),
    'PKCE authorize must use public client ctem-web',
  ).toBe('ctem-web');
  expect(authorize.searchParams.get('response_type')).toBe('code');
  expect(authorize.searchParams.get('code_challenge_method'), 'authorize must use S256 PKCE').toBe(
    'S256',
  );
  expect(authorize.searchParams.get('code_challenge')).toBeTruthy();
  expect(authorize.searchParams.get('redirect_uri')).toMatch(/\/login\/callback$/);
}

export async function submitKeycloakLogin(page: Page): Promise<void> {
  const username = page.locator('#username');
  const password = page.locator('#password');
  const submit = page.locator('#kc-login');
  await expect(
    username,
    'Keycloak username field missing — realm import may have failed',
  ).toBeVisible({
    timeout: 30_000,
  });
  await expect(password, 'Keycloak password field missing').toBeVisible();
  await username.fill(DEMO_USERNAME);
  await password.fill(DEMO_PASSWORD);
  await submit.click();
}

/**
 * Full browser OIDC: CTEM /login → Keycloak analyst/demo → PKCE callback → JWT.
 * Lands on /findings. Fail-closed if the session is missing or is a PAT.
 */
export async function loginAsDemoAnalyst(page: Page): Promise<string> {
  await page.goto('/login');
  await expectCtemLoginHasNoSecretFields(page);
  await page.getByRole('button', { name: 'Sign in with Keycloak' }).click();
  await page.waitForURL(/\/(findings|login\/callback|realms\/ctem)/, { timeout: 30_000 });
  if (await page.locator('#username').isVisible()) {
    await submitKeycloakLogin(page);
  }
  await page.waitForURL(/\/findings/, { timeout: 30_000 });
  await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();
  return expectJwtSession(page);
}

/**
 * Replay `/login/callback` with the same authorization code. Strict Mode and a
 * second completeAuthorization must keep the stored JWT (not log out).
 */
export async function expectSameCodeCallbackKeepsSession(
  page: Page,
  callbackUrl: string,
): Promise<void> {
  if (!callbackUrl.includes('code=')) {
    throw new Error(
      'Need the original /login/callback?code=… URL to replay completeAuthorization with the same code',
    );
  }
  const before = await expectJwtSession(page);
  await page.goto(callbackUrl);
  await page.waitForURL(/\/findings/, { timeout: 15_000 });
  await expectStillSignedIn(page);
  const after = await expectJwtSession(page);
  expect(after, 'second completeAuthorization with the same code must keep the JWT').toBe(before);
}

import { expect, test } from '@playwright/test';
import {
  expectCallbackRemountKeepsSession,
  expectCtemLoginHasNoSecretFields,
  startKeycloakAuthorize,
  submitKeycloakLogin,
} from './helpers/auth';
import { expectJwtSession, expectStillSignedIn, readAllSessionStorage } from './helpers/session';

test.describe('OIDC login / PKCE callback', () => {
  test.describe.configure({ timeout: 90_000 });

  test('Keycloak demo analyst stores a JWT and Strict Mode remount keeps the session', async ({
    page,
  }) => {
    await startKeycloakAuthorize(page);
    await expect(page.locator('#username')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
    await submitKeycloakLogin(page);
    await page.waitForURL(/\/findings/, { timeout: 30_000 });
    await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();
    const jwt = await expectJwtSession(page);
    expect(
      jwt.split('.').length,
      'session must be a three-part JWT, not a PAT or opaque token',
    ).toBe(3);

    const storage = await readAllSessionStorage(page);
    expect(JSON.stringify(storage)).not.toMatch(/ctem_pat_/);

    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await expect(page.getByText(/^owner$/i)).toBeVisible();

    await expectCallbackRemountKeepsSession(page);
    await expectStillSignedIn(page);
    await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();
  });

  test('CTEM /login has no password field, JWT paste, or PAT prompt', async ({ page }) => {
    await page.goto('/login');
    await expectCtemLoginHasNoSecretFields(page);
    await expect(page.locator('form')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Sign in with Keycloak' })).toHaveCount(1);
  });
});

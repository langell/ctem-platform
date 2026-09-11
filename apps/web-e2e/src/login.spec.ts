import { expect, test } from '@playwright/test';
import {
  expectCtemLoginHasNoSecretFields,
  expectSameCodeCallbackKeepsSession,
  startKeycloakAuthorize,
  submitKeycloakLogin,
} from './helpers/auth';
import { expectJwtSession, expectStillSignedIn, readAllSessionStorage } from './helpers/session';

test.describe('OIDC login / PKCE callback', () => {
  test.describe.configure({ timeout: 90_000 });

  test('one Keycloak button, no paste fields, same-code double callback keeps session', async ({
    page,
  }) => {
    await page.goto('/login');
    await expectCtemLoginHasNoSecretFields(page);
    await expect(page.locator('aside.dock')).toHaveCount(0);
    await expect(page.locator('form')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Sign in with Keycloak' })).toHaveCount(1);
    await expect(page.getByRole('button')).toHaveCount(1);

    let callbackWithCode = '';
    page.on('framenavigated', (frame) => {
      if (frame !== page.mainFrame()) return;
      const url = frame.url();
      if (url.includes('/login/callback') && url.includes('code=')) {
        callbackWithCode = url;
      }
    });

    await startKeycloakAuthorize(page);
    await submitKeycloakLogin(page);
    await page.waitForURL(/\/findings/, { timeout: 30_000 });
    await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();
    await expect(page.locator('aside.dock')).toBeVisible();
    await expect(page.locator('header.topbar')).toHaveCount(0);

    const jwt = await expectJwtSession(page);
    expect(jwt.split('.').length, 'session must be a three-part JWT, not a PAT').toBe(3);
    const storage = await readAllSessionStorage(page);
    expect(JSON.stringify(storage)).not.toMatch(/ctem_pat_/);
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();

    if (!callbackWithCode) {
      throw new Error(
        'OIDC callback URL with code was never observed — cannot assert two completeAuthorization calls',
      );
    }
    await expectSameCodeCallbackKeepsSession(page, callbackWithCode);
    await expectStillSignedIn(page);
    await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();
  });
});

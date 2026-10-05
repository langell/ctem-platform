import { expect, test } from '@playwright/test';
import { signUpFreshOwner } from './helpers/signup';

const TOKEN = 'ghs_e2e_stub_token_do_not_leak';

test.describe('connect github', () => {
  test.describe.configure({ timeout: 180_000 });

  test('a new owner connects GitHub and sees that org repositories', async ({ page, request }) => {
    await signUpFreshOwner(page);

    await expect(page.getByRole('link', { name: 'Integrations' })).toBeVisible();
    await page.getByRole('link', { name: 'Integrations' }).click();
    await expect(page.getByRole('heading', { name: 'Connect GitHub' })).toBeVisible();

    await page.getByLabel('Owner').fill('acme');
    await page.getByLabel('Account type').selectOption('org');
    await page.getByLabel('Token').fill(TOKEN);

    const posted = page.waitForResponse(
      (res) => res.url().includes('/v1/integrations/github') && res.request().method() === 'POST',
    );
    await page.getByRole('button', { name: 'Connect GitHub' }).click();
    const response = await posted;
    expect(response.status()).toBe(201);
    const responseText = await response.text();
    expect(responseText).not.toContain(TOKEN);
    const body = JSON.parse(responseText) as {
      displayName?: string;
      lastSyncError?: string | null;
      credentialRef?: string;
      token?: string;
    };
    expect(body.displayName).toBe('github:acme');
    expect(body.lastSyncError).toBeNull();
    expect(body).not.toHaveProperty('credentialRef');
    expect(body).not.toHaveProperty('token');

    const seen = await request.get('http://127.0.0.1:4019/__requests');
    expect(seen.ok()).toBeTruthy();
    const recorded = (await seen.json()) as {
      requests: { method: string; path: string; status: number }[];
    };
    expect(JSON.stringify(recorded)).not.toContain(TOKEN);
    expect(recorded.requests).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ method: 'GET', path: '/user', status: 200 }),
      ]),
    );

    await expect(page.getByText('github:acme')).toBeVisible();
    await expect(page.getByText('Synced', { exact: true })).toBeVisible();
    await expect(page.locator('input[name="token"]')).toHaveValue('');
    expect(await page.content()).not.toContain(TOKEN);

    await page.getByRole('link', { name: 'Assets' }).click();
    await expect(page.getByRole('heading', { name: 'Assets' })).toBeVisible();
    await expect(page.getByText('payments-api')).toBeVisible();
    await expect(page.getByText('github:acme/payments-api')).toBeVisible();
    await expect(page.getByText('web', { exact: true })).toBeVisible();
    expect(await page.content()).not.toContain(TOKEN);
  });
});

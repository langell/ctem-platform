import { expect, test, type Response } from '@playwright/test';
import { loginAsDemoAnalyst } from './helpers/auth';
import { expectJwtSession, isJwtAccessToken, readAllSessionStorage } from './helpers/session';

function isScanCreate(response: Response): boolean {
  if (response.request().method() !== 'POST') return false;
  const url = new URL(response.url());
  return url.pathname === '/v1/scans';
}

test.describe('Scan kick smoke', () => {
  test.describe.configure({ timeout: 90_000 });

  test('Keycloak JWT session POSTs /v1/scans 2xx and shows a queued card with id', async ({
    page,
  }) => {
    await loginAsDemoAnalyst(page);
    const jwt = await expectJwtSession(page);

    await page.getByRole('link', { name: 'Scan' }).click();
    await expect(page.getByRole('heading', { name: 'Scan' })).toBeVisible();
    await expect(page.locator('input[type="password"]')).toHaveCount(0);
    await expect(page.locator('textarea')).toHaveCount(0);

    const create = page.waitForResponse(isScanCreate, { timeout: 20_000 });
    await page.getByRole('button', { name: 'Start scan' }).click();
    const response = await create;

    expect(response.status(), 'scan kick must be 2xx, never HTTP 500').toBeGreaterThanOrEqual(200);
    expect(response.status(), 'scan kick must be 2xx').toBeLessThan(300);

    const auth = response.request().headers().authorization ?? '';
    expect(auth.startsWith('Bearer '), 'scan kick must send the Keycloak JWT').toBe(true);
    const bearer = auth.slice('Bearer '.length);
    expect(isJwtAccessToken(bearer), 'scan kick must not send a PAT').toBe(true);
    expect(bearer).toBe(jwt);
    expect(bearer).not.toMatch(/ctem_pat_/);

    const url = new URL(response.url());
    expect(url.search, 'org must come from the JWT, not the query').not.toMatch(/org/i);
    expect(response.request().headers()['x-ctem-org']).toBeUndefined();
    expect(response.request().headers()['x-org-id']).toBeUndefined();

    const body = response.request().postDataJSON() as Record<string, unknown> | null;
    if (!body || typeof body !== 'object') {
      throw new Error('Scan kick body was empty — fail-closed');
    }
    expect(body, 'org must come from the JWT, not the scan body').not.toHaveProperty('orgId');
    expect(body, 'org must come from the JWT, not the scan body').not.toHaveProperty('org_id');

    const card = page.locator('article.card').filter({ has: page.locator('code') });
    await expect(card, 'scan kick must show the queued result card').toBeVisible({
      timeout: 15_000,
    });
    await expect(card.getByRole('heading', { name: 'Queued' })).toBeVisible();
    const id = (await card.locator('code').innerText()).trim();
    if (!id) {
      throw new Error('Queued scan card is missing an id');
    }
    expect(id, 'queued card must show the scan id').toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );

    await expect(page.locator('.banner.error')).toHaveCount(0);
    await expect(page.getByText(/HTTP 500|Internal Server Error/i)).toHaveCount(0);

    const storage = await readAllSessionStorage(page);
    expect(JSON.stringify(storage)).not.toMatch(/ctem_pat_/);
    await expectJwtSession(page);
  });
});

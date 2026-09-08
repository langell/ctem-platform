import { expect, test, type Response } from '@playwright/test';
import { loginAsDemoAnalyst } from './helpers/auth';

function isScanCreate(response: Response): boolean {
  if (response.request().method() !== 'POST') return false;
  const url = new URL(response.url());
  return url.pathname === '/v1/scans';
}

test.describe('Scan kick smoke', () => {
  test.describe.configure({ timeout: 90_000 });

  test('starting a container (or available) scan is not a gateway 500', async ({ page }) => {
    await loginAsDemoAnalyst(page);
    await page.getByRole('link', { name: 'Scan' }).click();
    await expect(page.getByRole('heading', { name: 'Scan' })).toBeVisible();
    await expect(page.locator('input[type="password"]')).toHaveCount(0);
    await expect(page.locator('textarea')).toHaveCount(0);

    const select = page.locator('form select');
    await expect(select, 'Scan page must expose a scanner select').toBeVisible();
    const values = await select
      .locator('option')
      .evaluateAll((opts) => opts.map((el) => (el as HTMLOptionElement).value).filter(Boolean));
    if (values.length === 0) {
      throw new Error('Scan: no scanner options — incomplete UI is not a pass');
    }
    const scanner = values.includes('container') ? 'container' : values[0];
    await select.selectOption(scanner);

    const create = page.waitForResponse(isScanCreate, { timeout: 20_000 });
    await page.getByRole('button', { name: 'Start scan' }).click();
    const response = await create;

    expect(response.status(), `scan kick must not be a gateway 500 (scanner=${scanner})`).not.toBe(
      500,
    );
    expect(response.status(), 'scan kick produced no HTTP status').toBeGreaterThan(0);
    expect(response.status(), `unexpected 5xx on scan kick (scanner=${scanner})`).toBeLessThan(500);

    const body = response.request().postDataJSON() as Record<string, unknown> | null;
    if (!body || typeof body !== 'object') {
      throw new Error('Scan kick body was empty — fail-closed');
    }
    expect(body, 'org must come from the JWT, not the scan body').not.toHaveProperty('orgId');
    expect(body, 'org must come from the JWT, not the scan body').not.toHaveProperty('org_id');
    expect(body.scannerType).toBe(scanner);

    const result = page.locator('article.card').filter({ has: page.locator('code') });
    const error = page.locator('form .banner.error, section .banner.error');
    await expect(
      result.or(error),
      'scan kick must show a result card or a fail-closed error',
    ).toBeVisible({
      timeout: 15_000,
    });

    if ((await result.count()) > 0) {
      await expect(result.locator('code')).not.toHaveText('');
      return;
    }

    const message = (await error.innerText()).trim();
    if (!message) {
      throw new Error('Scan kick error banner was empty — incomplete outcome is not a pass');
    }
    expect(message, 'fail-closed UI must not be a gateway 500').not.toMatch(
      /500|Internal Server Error/i,
    );
  });
});

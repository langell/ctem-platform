import { expect, test, type Page } from '@playwright/test';
import { loginAsDemoAnalyst } from './helpers/auth';

const COLUMNS = ['Title', 'Severity', 'Risk', 'State', 'Validation', 'Scanner'] as const;
const RAIL = /(?:^|\s)rail-(?:danger|warn|accent|info|muted)(?:\s|$)/;
const BAND = /(?:^|\s)risk-band-(?:high|mid|low)(?:\s|$)/;

function findingsListUrl(url: URL): boolean {
  return url.pathname === '/v1/findings' || url.pathname === '/v1/findings/';
}

async function expectSixColumns(page: Page): Promise<void> {
  const headers = page.locator('thead th');
  await expect(headers, 'Score Rail must keep the six existing columns').toHaveCount(
    COLUMNS.length,
  );
  await expect(headers).toHaveText([...COLUMNS]);
}

test.describe('Findings Score Rail', () => {
  test.describe.configure({ timeout: 90_000 });

  test('six columns, every data row has rail + risk-band, whole-row opens detail', async ({
    page,
  }) => {
    await loginAsDemoAnalyst(page);
    await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();
    await expect(page.locator('tbody .skeleton')).toHaveCount(0, { timeout: 20_000 });

    const error = page.locator('section .banner.error');
    if (await error.count()) {
      throw new Error(`Findings failed to load: ${await error.innerText()}`);
    }
    await expect(page.locator('.empty-title')).toHaveCount(0);

    await expectSixColumns(page);

    const rows = page.locator('tbody tr.clickable');
    const rowCount = await rows.count();
    if (rowCount < 1) {
      throw new Error(
        'Score Rail: expected seeded findings with rail/band classes; an empty table is not a pass',
      );
    }

    for (let i = 0; i < rowCount; i += 1) {
      const row = rows.nth(i);
      const rowClass = (await row.getAttribute('class')) ?? '';
      if (!RAIL.test(rowClass)) {
        throw new Error(`Score Rail: data row ${i} missing rail-* class, got "${rowClass}"`);
      }
      const riskClass = (await row.locator('td.risk-cell > div').getAttribute('class')) ?? '';
      if (!BAND.test(riskClass)) {
        throw new Error(`Score Rail: data row ${i} missing risk-band-* class, got "${riskClass}"`);
      }
    }

    const first = rows.first();
    const title = (await first.locator('a.finding-title').innerText()).trim();
    if (!title) {
      throw new Error('Score Rail: finding title link is empty');
    }
    await first.locator('td').nth(1).click();
    await expect(page).toHaveURL(/\/findings\/[0-9a-f-]{36}$/i);
    await expect(page.locator('.skeleton-title')).toHaveCount(0, { timeout: 20_000 });
    const detailError = page.locator('section .banner.error');
    if (await detailError.count()) {
      throw new Error(`Finding detail failed to load: ${await detailError.innerText()}`);
    }
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(title);
  });

  test('skeleton, empty, and error states stay distinct', async ({ page }) => {
    await loginAsDemoAnalyst(page);

    const listOnly = (url: URL) => findingsListUrl(url);
    let release: (() => void) | undefined;
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    await page.route(listOnly, async (route) => {
      if (route.request().method() !== 'GET') {
        await route.continue();
        return;
      }
      await hold;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ items: [], nextCursor: null }),
      });
    });
    await page.goto('/findings');
    await expect(page.locator('tbody .skeleton'), 'loading paints skeleton rows').toBeVisible();
    await expectSixColumns(page);
    await expect(page.locator('.count')).toHaveCount(0);
    await expect(page.locator('.empty-title')).toHaveCount(0);
    await expect(page.locator('section .banner.error')).toHaveCount(0);
    await expect(page.locator('tbody tr.clickable')).toHaveCount(0);

    release!();
    await expect(page.locator('tbody .skeleton')).toHaveCount(0, { timeout: 15_000 });
    await expect(
      page.locator('.empty-title'),
      'empty copy is not a skeleton or error',
    ).toBeVisible();
    await expect(page.locator('.empty-copy')).toBeVisible();
    await expect(page.locator('section .banner.error')).toHaveCount(0);
    await expect(page.locator('tbody tr.clickable')).toHaveCount(0);
    await expect(page.locator('tbody tr[class*="rail-"]')).toHaveCount(0);
    await expect(page.locator('.risk-band-high, .risk-band-mid, .risk-band-low')).toHaveCount(0);
    await page.unrouteAll();

    await page.route(listOnly, async (route) => {
      if (route.request().method() !== 'GET') {
        await route.continue();
        return;
      }
      await route.fulfill({
        status: 502,
        contentType: 'application/json',
        body: JSON.stringify({ title: 'Gateway error 502' }),
      });
    });
    await page.goto('/findings');
    await expect(page.locator('tbody .skeleton')).toHaveCount(0, { timeout: 15_000 });
    await expect(
      page.locator('section .banner.error'),
      'error banner is not the empty copy',
    ).toBeVisible();
    await expect(page.locator('.empty-title')).toHaveCount(0);
    await expect(page.locator('.count')).toHaveCount(0);
    await expect(page.locator('tbody tr.clickable')).toHaveCount(0);
  });
});

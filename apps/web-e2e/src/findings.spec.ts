import { expect, test } from '@playwright/test';
import { loginAsDemoAnalyst } from './helpers/auth';

const COLUMNS = ['Title', 'Severity', 'Risk', 'State', 'Validation', 'Scanner'] as const;
const RAIL_CLASSES = [
  'rail-danger',
  'rail-warn',
  'rail-accent',
  'rail-info',
  'rail-muted',
] as const;
const BAND_CLASSES = ['risk-band-high', 'risk-band-mid', 'risk-band-low'] as const;

test.describe('Findings Score Rail', () => {
  test.describe.configure({ timeout: 90_000 });

  test('six columns, severity rail + risk-band paint, whole-row click opens detail', async ({
    page,
  }) => {
    await loginAsDemoAnalyst(page);
    await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();

    await expect(page.locator('tbody .skeleton')).toHaveCount(0, { timeout: 20_000 });

    const error = page.locator('section .banner.error');
    if (await error.count()) {
      throw new Error(`Findings failed to load: ${await error.innerText()}`);
    }

    const headers = page.locator('thead th');
    await expect(headers, 'Score Rail must keep the six existing columns').toHaveCount(
      COLUMNS.length,
    );
    await expect(headers).toHaveText([...COLUMNS]);

    const rows = page.locator('tbody tr.clickable');
    const rowCount = await rows.count();
    if (rowCount < 1) {
      throw new Error(
        'Score Rail: expected seeded findings with rail/band classes; an empty table is not a pass',
      );
    }

    const first = rows.first();
    const rowClass = (await first.getAttribute('class')) ?? '';
    const hasRail = RAIL_CLASSES.some((cls) => rowClass.split(/\s+/).includes(cls));
    if (!hasRail) {
      throw new Error(`Score Rail: first data row missing severity rail class, got "${rowClass}"`);
    }

    const risk = first.locator('td.risk-cell > div');
    await expect(risk, 'risk cell must paint a score').not.toHaveText('');
    const riskClass = (await risk.getAttribute('class')) ?? '';
    const hasBand = BAND_CLASSES.some((cls) => riskClass.split(/\s+/).includes(cls));
    if (!hasBand) {
      throw new Error(`Score Rail: risk cell missing risk-band class, got "${riskClass}"`);
    }

    const title = (await first.locator('a.finding-title').innerText()).trim();
    if (!title) {
      throw new Error('Score Rail: finding title link is empty');
    }

    // Click a non-link cell so this is the whole-row handler, not the <Link>.
    await first.locator('td').nth(1).click();
    await expect(page).toHaveURL(/\/findings\/[0-9a-f-]{36}/i);
    await expect(page.locator('.skeleton-title')).toHaveCount(0, { timeout: 20_000 });
    const detailError = page.locator('section .banner.error');
    if (await detailError.count()) {
      throw new Error(`Finding detail failed to load: ${await detailError.innerText()}`);
    }
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(title);
    await expect(page.getByRole('link', { name: 'Findings' })).toBeVisible();
  });
});

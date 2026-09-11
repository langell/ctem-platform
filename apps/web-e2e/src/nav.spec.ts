import { expect, test } from '@playwright/test';
import { loginAsDemoAnalyst } from './helpers/auth';
import { clickOwnerDockLink, expectOwnerDockActive, ownerDock } from './helpers/nav';

const OPS_ADMIN: ReadonlyArray<{ link: string; heading: string; path: RegExp }> = [
  { link: 'Assets', heading: 'Assets', path: /\/assets$/ },
  { link: 'Findings', heading: 'Findings', path: /\/findings$/ },
  { link: 'Scan', heading: 'Scan', path: /\/scans$/ },
  { link: 'Policies', heading: 'Policies', path: /\/policies$/ },
  { link: 'Members', heading: 'Members', path: /\/members$/ },
];

test.describe('Owner Dock', () => {
  test.describe.configure({ timeout: 90_000 });

  test('login has no dock; Ops then Admin navigate existing routes', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('aside.dock')).toHaveCount(0);
    await expect(page.locator('header.topbar')).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'CTEM' })).toBeVisible();
    await expect(page.getByText('Sign in to continue')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign in with Keycloak' })).toBeVisible();
    await expect(page.getByRole('link')).toHaveCount(0);

    await loginAsDemoAnalyst(page);
    const dock = ownerDock(page);
    await expect(dock).toBeVisible();
    await expect(page.locator('header.topbar')).toHaveCount(0);
    await expect(dock.getByText('Ops', { exact: true })).toBeVisible();
    await expect(dock.getByText('Admin', { exact: true })).toBeVisible();
    await expect(dock.locator('.nav-group-label')).toHaveText(['Ops', 'Admin']);
    await expectOwnerDockActive(page, 'Findings');

    for (const hop of OPS_ADMIN) {
      await clickOwnerDockLink(page, hop.link);
      await expect(page).toHaveURL(hop.path);
      await expect(page.getByRole('heading', { name: hop.heading })).toBeVisible();
      await expectOwnerDockActive(page, hop.link);
      await expect(ownerDock(page)).toBeVisible();
    }

    await clickOwnerDockLink(page, 'Findings');
    await expect(page.locator('tbody .skeleton')).toHaveCount(0, { timeout: 20_000 });
    const row = page.locator('tbody tr.clickable').first();
    await expect(
      row,
      'seeded findings required to assert /findings/:id stays on Findings',
    ).toBeVisible();
    await row.locator('td').nth(1).click();
    await expect(page).toHaveURL(/\/findings\/[0-9a-f-]{36}$/i);
    await expectOwnerDockActive(page, 'Findings');
    await expect(ownerDock(page).getByRole('button', { name: 'Sign out' })).toBeVisible();
  });
});

import { expect, test } from '@playwright/test';
import { DEMO_ORG_ID } from './helpers/session';
import { signUpFreshOwner } from './helpers/signup';

test.describe('org signup', () => {
  test.describe.configure({ timeout: 120_000 });

  test('a new IdP user creates one org and lands as owner', async ({ page }) => {
    const owner = await signUpFreshOwner(page);
    expect(owner.orgId).not.toBe(DEMO_ORG_ID);
    expect(owner.slug.startsWith('e2e-')).toBe(true);
    await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();
    await expect(page.locator('aside.dock .session span').first()).toHaveText('owner');
  });
});

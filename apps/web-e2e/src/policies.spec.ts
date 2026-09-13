import { expect, test, type Page, type Response } from '@playwright/test';
import { loginAsDemoAnalyst } from './helpers/auth';
import { clickOwnerDockLink, expectOwnerDockActive, ownerDock } from './helpers/nav';
import { expectJwtSession, isJwtAccessToken } from './helpers/session';

function policiesUrl(url: URL): boolean {
  return url.pathname === '/v1/policies' || url.pathname === '/v1/policies/';
}

function isPolicyCreate(response: Response): boolean {
  return response.request().method() === 'POST' && policiesUrl(new URL(response.url()));
}

function isPolicyUpdate(response: Response): boolean {
  if (response.request().method() !== 'PATCH') return false;
  return /\/v1\/policies\/[0-9a-f-]{36}\/?$/i.test(new URL(response.url()).pathname);
}

async function openPolicies(page: Page): Promise<void> {
  await clickOwnerDockLink(page, 'Policies');
  await expect(page.getByRole('heading', { name: 'Policies' })).toBeVisible();
  await expect(page.locator('tbody .skeleton')).toHaveCount(0, { timeout: 20_000 });
  const error = page.locator('section .banner.error');
  if (await error.count()) {
    throw new Error(`Policies failed to load: ${await error.innerText()}`);
  }
}

test.describe('Policies block_deploy editor', () => {
  test.describe.configure({ timeout: 90_000 });

  test('Owner Dock Policies create and edit persist block_deploy', async ({ page }) => {
    const jwt = await loginAsDemoAnalyst(page);
    await openPolicies(page);
    await expectOwnerDockActive(page, 'Policies');
    await expect(ownerDock(page)).toBeVisible();
    await expect(page).toHaveURL(/\/policies$/);

    const action = page.getByLabel('Action');
    await expect(action.locator('option[value="block_deploy"]')).toHaveCount(1);
    await expect(action.locator('option[value="notify,block_deploy"]')).toHaveCount(1);
    await expect(action.locator('option[value="fail_build,block_deploy"]')).toHaveCount(1);

    const name = `e2e-block-deploy-${Date.now()}`;
    await page.getByLabel('Name').fill(name);
    await action.selectOption('block_deploy');

    const create = page.waitForResponse(isPolicyCreate, { timeout: 20_000 });
    await page.getByRole('button', { name: 'Create rule' }).click();
    const createRes = await create;
    expect(createRes.status(), 'policy create must be 2xx').toBeGreaterThanOrEqual(200);
    expect(createRes.status()).toBeLessThan(300);

    const createAuth = createRes.request().headers().authorization ?? '';
    expect(createAuth.startsWith('Bearer ')).toBe(true);
    expect(isJwtAccessToken(createAuth.slice('Bearer '.length))).toBe(true);
    expect(createAuth.slice('Bearer '.length)).toBe(jwt);

    const createBody = createRes.request().postDataJSON() as Record<string, unknown>;
    expect(createBody).not.toHaveProperty('orgId');
    expect(createBody.actions).toEqual(['block_deploy']);
    expect(createBody).not.toHaveProperty('conclusion');
    expect(createBody).not.toHaveProperty('deployConclusion');

    const created = (await createRes.json()) as { id?: string; actions?: string[] };
    expect(created.actions, 'create must persist block_deploy').toEqual(['block_deploy']);

    const row = page.locator('tbody tr').filter({ hasText: name });
    await expect(row).toBeVisible({ timeout: 15_000 });
    await expect(row).toContainText('Block deploy');

    await row.getByRole('button', { name: 'Edit' }).click();
    await expect(page.getByRole('heading', { name: 'Update rule' })).toBeVisible();
    await expect(action).toHaveValue('block_deploy');
    await action.selectOption('notify,block_deploy');

    const update = page.waitForResponse(isPolicyUpdate, { timeout: 20_000 });
    await page.getByRole('button', { name: 'Update rule' }).click();
    const updateRes = await update;
    expect(updateRes.status(), 'policy update must be 2xx').toBeGreaterThanOrEqual(200);
    expect(updateRes.status()).toBeLessThan(300);

    const updateBody = updateRes.request().postDataJSON() as Record<string, unknown>;
    expect(updateBody).not.toHaveProperty('orgId');
    expect(updateBody.actions).toEqual(['notify', 'block_deploy']);

    const updated = (await updateRes.json()) as { actions?: string[] };
    expect(updated.actions, 'edit must persist notify + block_deploy').toEqual([
      'notify',
      'block_deploy',
    ]);

    await expect(row).toContainText('Notify');
    await expect(row).toContainText('Block deploy');
    await expect(page).toHaveURL(/\/policies$/);
    await expectOwnerDockActive(page, 'Policies');
    await expectJwtSession(page);
  });
});

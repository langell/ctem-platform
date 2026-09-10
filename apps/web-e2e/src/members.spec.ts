import { expect, test, type Locator, type Page, type Response } from '@playwright/test';
import { loginAsDemoAnalyst } from './helpers/auth';
import { expectJwtSession, isJwtAccessToken } from './helpers/session';

/** Role / status badges — not the Actions <select> options that repeat the same labels. */
function roleBadge(row: Locator): Locator {
  return row.locator('td').nth(1).locator('.badge');
}

function statusBadge(row: Locator): Locator {
  return row.locator('td').nth(2).locator('.badge');
}

function membersUrl(url: URL): boolean {
  return url.pathname === '/v1/org/members' || url.pathname === '/v1/org/members/';
}

function isMemberInvite(response: Response): boolean {
  return response.request().method() === 'POST' && membersUrl(new URL(response.url()));
}

function isMemberSetRole(response: Response): boolean {
  if (response.request().method() !== 'PATCH') return false;
  return /\/v1\/org\/members\/[^/]+\/role\/?$/.test(new URL(response.url()).pathname);
}

function isMemberDisable(response: Response): boolean {
  if (response.request().method() !== 'DELETE') return false;
  return /\/v1\/org\/members\/[^/]+\/?$/.test(new URL(response.url()).pathname);
}

async function openMembers(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Members' }).click();
  await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
  await expect(page.locator('tbody .skeleton')).toHaveCount(0, { timeout: 20_000 });
  const error = page.locator('section .banner.error');
  if (await error.count()) {
    throw new Error(`Members failed to load: ${await error.innerText()}`);
  }
}

test.describe('Members admin', () => {
  test.describe.configure({ timeout: 90_000 });

  test('Keycloak member:manage can list, invite, setRole, and disable with confirm', async ({
    page,
  }) => {
    const jwt = await loginAsDemoAnalyst(page);
    await openMembers(page);

    await expect(page.getByRole('columnheader', { name: 'Member' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Role' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Status' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Actions' })).toBeVisible();

    const ownerRow = page.locator('tbody tr').filter({ hasText: 'security@demo.test' });
    const teammateRow = page.locator('tbody tr').filter({ hasText: 'developer@demo.test' });
    await expect(roleBadge(ownerRow)).toHaveText('Owner');
    await expect(statusBadge(ownerRow)).toHaveText('Active');
    await expect(roleBadge(teammateRow)).toHaveText('Developer');
    await expect(statusBadge(teammateRow)).toHaveText('Active');

    const inviteEmail = `invitee-${Date.now()}@demo.test`;
    await page.getByLabel('Email').fill(inviteEmail);
    await page.getByLabel('Invite role').selectOption('developer');
    const invite = page.waitForResponse(isMemberInvite, { timeout: 20_000 });
    await page.getByRole('button', { name: 'Invite' }).click();
    const inviteRes = await invite;
    expect(inviteRes.status(), 'invite must be 201').toBe(201);
    const inviteAuth = inviteRes.request().headers().authorization ?? '';
    expect(inviteAuth.startsWith('Bearer ')).toBe(true);
    expect(isJwtAccessToken(inviteAuth.slice('Bearer '.length))).toBe(true);
    expect(inviteAuth.slice('Bearer '.length)).toBe(jwt);
    const inviteBody = inviteRes.request().postDataJSON() as Record<string, unknown>;
    expect(inviteBody).not.toHaveProperty('orgId');
    expect(inviteBody.email).toBe(inviteEmail);
    expect(inviteBody.role).toBe('developer');
    await expect(page.getByLabel('Email')).toHaveValue('');
    await expect(page.getByRole('button', { name: 'Invite' })).toBeEnabled();
    await expect(page.locator('tbody tr').filter({ hasText: inviteEmail })).toHaveCount(0);

    await teammateRow.getByLabel('Role for developer@demo.test').selectOption('auditor');
    const setRole = page.waitForResponse(isMemberSetRole, { timeout: 20_000 });
    await teammateRow.getByRole('button', { name: 'Save' }).click();
    const setRoleRes = await setRole;
    expect(setRoleRes.status(), 'setRole must be 2xx').toBeGreaterThanOrEqual(200);
    expect(setRoleRes.status()).toBeLessThan(300);
    await expect(roleBadge(teammateRow)).toHaveText('Auditor');

    await teammateRow.getByRole('button', { name: 'Disable' }).click();
    const dialog = page.locator('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('heading', { name: 'Disable member?' })).toBeVisible();
    const disable = page.waitForResponse(isMemberDisable, { timeout: 20_000 });
    await dialog.getByRole('button', { name: 'Disable member' }).click();
    const disableRes = await disable;
    expect(disableRes.status(), 'disable must be 2xx').toBeGreaterThanOrEqual(200);
    expect(disableRes.status()).toBeLessThan(300);
    await expect(dialog).toBeHidden();
    await expect(statusBadge(teammateRow)).toHaveText('Disabled');
    await expect(teammateRow.getByRole('button', { name: 'Disable' })).toHaveCount(0);

    await ownerRow.getByRole('button', { name: 'Disable' }).click();
    await expect(dialog).toBeVisible();
    const lastOwner = page.waitForResponse(isMemberDisable, { timeout: 20_000 });
    await dialog.getByRole('button', { name: 'Disable member' }).click();
    expect((await lastOwner).status()).toBe(403);
    await expect(page.locator('section .banner.error')).toContainText(/last owner/i);
    await expect(statusBadge(ownerRow)).toHaveText('Active');

    await expectJwtSession(page);
  });

  test('without member:manage write controls are absent', async ({ page }) => {
    await loginAsDemoAnalyst(page);

    await page.route('**/v1/session', async (route) => {
      if (route.request().method() !== 'GET') {
        await route.continue();
        return;
      }
      const upstream = await route.fetch();
      const body = (await upstream.json()) as {
        permissions?: string[];
        [key: string]: unknown;
      };
      const permissions = (body.permissions ?? []).filter((p) => p !== 'member:manage');
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ...body, role: 'developer', permissions }),
      });
    });

    await page.goto('/members');
    await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
    await expect(page.locator('tbody .skeleton')).toHaveCount(0, { timeout: 20_000 });
    await expect(page.getByText('security@demo.test')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Invite' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Save' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Disable' })).toHaveCount(0);
    await expect(page.getByRole('columnheader', { name: 'Actions' })).toHaveCount(0);
    await expect(page.getByLabel('Email')).toHaveCount(0);
    await expect(
      page.getByText('This role can read members. Managing requires member:manage.'),
    ).toBeVisible();
  });

  test('skeleton, empty, and error states stay distinct', async ({ page }) => {
    await loginAsDemoAnalyst(page);
    await page.goto('/scans');
    await expect(page.getByRole('heading', { name: 'Scan' })).toBeVisible();

    let releaseHold: (() => void) | undefined;
    const hold = new Promise<void>((resolve) => {
      releaseHold = resolve;
    });
    let intercepted = 0;
    await page.route(
      (url) => membersUrl(url),
      async (route) => {
        if (route.request().method() !== 'GET') {
          await route.continue();
          return;
        }
        intercepted += 1;
        await hold;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([]),
        });
      },
    );

    await page.goto('/members');
    await expect.poll(() => intercepted, { timeout: 15_000 }).toBeGreaterThan(0);
    await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
    const skeleton = page.locator('tbody .skeleton');
    if ((await skeleton.count()) > 0) {
      await expect(skeleton.first(), 'loading paints skeleton rows').toBeVisible();
    }
    await expect(page.locator('.count')).toHaveCount(0);
    await expect(page.locator('.empty-title')).toHaveCount(0);
    await expect(page.locator('section .banner.error')).toHaveCount(0);

    releaseHold!();
    await expect(skeleton).toHaveCount(0, { timeout: 15_000 });
    await expect(
      page.locator('.empty-title'),
      'empty copy is not a skeleton or error',
    ).toBeVisible();
    await expect(page.locator('.empty-copy')).toBeVisible();
    await expect(page.locator('section .banner.error')).toHaveCount(0);
    await page.unrouteAll();

    await page.route(
      (url) => membersUrl(url),
      async (route) => {
        if (route.request().method() !== 'GET') {
          await route.continue();
          return;
        }
        await route.fulfill({
          status: 502,
          contentType: 'application/json',
          body: JSON.stringify({ title: 'Gateway error 502' }),
        });
      },
    );
    await page.goto('/scans');
    await page.goto('/members');
    await expect(page.locator('tbody .skeleton')).toHaveCount(0, { timeout: 15_000 });
    await expect(
      page.locator('section .banner.error'),
      'error banner is not the empty copy',
    ).toBeVisible();
    await expect(page.locator('.empty-title')).toHaveCount(0);
    await expect(page.locator('.count')).toHaveCount(0);
  });
});

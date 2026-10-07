import { expect, test, type Page } from '@playwright/test';
import { registerFreshOwnerOnCreateOrg, type RegisteredOwner } from './helpers/signup';

test.describe('org signup double submit', () => {
  test.describe.configure({ timeout: 120_000 });

  test('double-click plus a concurrent second POST creates exactly one org and lands as owner', async ({
    page,
  }) => {
    const owner = await registerFreshOwnerOnCreateOrg(page);
    await page.getByLabel('Name').fill(owner.orgName);
    await page.getByLabel('Slug').fill(owner.slug);

    const posts: Array<{ status: number; id?: string }> = [];
    page.on('response', (res) => {
      if (!res.url().includes('/v1/orgs') || res.request().method() !== 'POST') return;
      const entry: { status: number; id?: string } = { status: res.status() };
      posts.push(entry);
      void res
        .json()
        .then((body: { id?: string }) => {
          if (typeof body?.id === 'string') entry.id = body.id;
        })
        .catch(() => undefined);
    });

    const otherSlug = `${owner.slug}-b`;
    await Promise.all([
      page.getByRole('button', { name: 'Create organization' }).dblclick(),
      page.evaluate(
        async ({ token, name, slug }) => {
          await fetch('/v1/orgs', {
            method: 'POST',
            headers: {
              authorization: `Bearer ${token}`,
              accept: 'application/json',
              'content-type': 'application/json',
            },
            body: JSON.stringify({ name, slug }),
          });
        },
        { token: owner.token, name: `${owner.orgName} B`, slug: otherSlug },
      ),
    ]);

    await page.waitForURL(/\/findings/, { timeout: 30_000 });
    await expect.poll(() => posts.filter((post) => post.status === 201 && post.id).length).toBe(1);

    expect(posts.filter((post) => post.status === 201)).toHaveLength(1);
    expect(posts.every((post) => post.status === 201 || post.status === 409)).toBe(true);
    expect(posts.some((post) => post.status >= 500)).toBe(false);
    expect(posts.filter((post) => post.status === 409).length).toBeGreaterThanOrEqual(1);

    await expect(page.locator('.error')).toHaveCount(0);
    await expect(page.locator('aside.dock .session span').first()).toHaveText('owner');

    const createdId = posts.find((post) => post.status === 201)?.id;
    const session = await readSession(page, owner.token);
    expect(session.status).toBe(200);
    expect(session.body.orgId).toBe(createdId);
  });

  test("a second tab's late submit gets 409 and still lands in the existing org", async ({
    page,
  }) => {
    const owner = await registerFreshOwnerOnCreateOrg(page);
    await page.getByLabel('Name').fill(owner.orgName);
    await page.getByLabel('Slug').fill(owner.slug);

    const created = await postOrg(page, owner, owner.orgName, owner.slug);
    expect(created.status).toBe(201);
    expect(created.body.id).toBeTruthy();

    const conflicted = page.waitForResponse(
      (res) => res.url().includes('/v1/orgs') && res.request().method() === 'POST',
    );
    await page.getByRole('button', { name: 'Create organization' }).click();
    expect((await conflicted).status()).toBe(409);

    await page.waitForURL(/\/findings/, { timeout: 30_000 });
    await expect(page.locator('.error')).toHaveCount(0);
    await expect(page.locator('aside.dock .session span').first()).toHaveText('owner');

    const session = await readSession(page, owner.token);
    expect(session.status).toBe(200);
    expect(session.body.orgId).toBe(created.body.id);
  });
});

function postOrg(page: Page, owner: RegisteredOwner, name: string, slug: string) {
  return page.evaluate(
    async ({ token, name: orgName, slug: orgSlug }) => {
      const res = await fetch('/v1/orgs', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          accept: 'application/json',
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: orgName, slug: orgSlug }),
      });
      return {
        status: res.status,
        body: (await res.json()) as { id?: string },
      };
    },
    { token: owner.token, name, slug },
  );
}

function readSession(page: Page, token: string) {
  return page.evaluate(async (bearer) => {
    const res = await fetch('/v1/session', {
      headers: { authorization: `Bearer ${bearer}`, accept: 'application/json' },
    });
    return {
      status: res.status,
      body: (await res.json()) as { orgId?: string; title?: string },
    };
  }, token);
}

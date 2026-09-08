import { expect, type Page } from '@playwright/test';

/** Must stay aligned with apps/web/src/api/client.ts */
export const TOKEN_STORAGE_KEY = 'ctem.gateway.token';
const PAT_PREFIX = 'ctem_pat_';

/** Compose Keycloak hard-codes this org_id on the demo analyst access token. */
export const DEMO_ORG_ID = 'c7e00000-0000-4000-8000-000000000001';

export function isJwtAccessToken(token: string): boolean {
  const value = token.trim();
  if (!value || value.startsWith(PAT_PREFIX)) return false;
  const parts = value.split('.');
  return parts.length === 3 && parts.every((part) => part.length > 0);
}

export function decodeJwtPayload(token: string): Record<string, unknown> {
  if (!isJwtAccessToken(token)) {
    throw new Error('Session token is not an access-token JWT');
  }
  const payload = token.split('.')[1];
  const padded = payload
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(payload.length / 4) * 4, '=');
  return JSON.parse(Buffer.from(padded, 'base64').toString('utf8')) as Record<string, unknown>;
}

export async function readSessionToken(page: Page): Promise<string | null> {
  return page.evaluate((key) => sessionStorage.getItem(key), TOKEN_STORAGE_KEY);
}

export async function readAllSessionStorage(page: Page): Promise<Record<string, string>> {
  return page.evaluate(() => {
    const out: Record<string, string> = {};
    for (let i = 0; i < sessionStorage.length; i += 1) {
      const key = sessionStorage.key(i);
      if (key) out[key] = sessionStorage.getItem(key) ?? '';
    }
    return out;
  });
}

/**
 * Fail-closed session bar: JWT stored, org from that JWT, no PAT anywhere
 * in sessionStorage. Empty/missing storage is a failure, not a skip.
 */
export async function expectJwtSession(page: Page): Promise<string> {
  const stored = await readAllSessionStorage(page);
  const token = stored[TOKEN_STORAGE_KEY];
  if (!token) {
    throw new Error(
      `Expected ${TOKEN_STORAGE_KEY} in sessionStorage after OIDC callback; keys were: ${
        Object.keys(stored).join(', ') || '(none)'
      }`,
    );
  }
  if (token.startsWith(PAT_PREFIX)) {
    throw new Error('Refusing a PAT in the browser session');
  }
  if (!isJwtAccessToken(token)) {
    throw new Error('Stored session is not an access-token JWT');
  }
  for (const [key, value] of Object.entries(stored)) {
    if (value.startsWith(PAT_PREFIX) || key.includes('ctem_pat_')) {
      throw new Error(`PAT leaked into sessionStorage under ${key}`);
    }
  }

  const payload = decodeJwtPayload(token);
  const orgId = payload.org_id;
  if (typeof orgId !== 'string' || !orgId) {
    throw new Error('JWT is missing org_id — org must come from the token, not the client');
  }
  expect(orgId, 'demo analyst JWT org_id must match the seeded Keycloak claim').toBe(DEMO_ORG_ID);
  return token;
}

export async function expectStillSignedIn(page: Page): Promise<void> {
  await expect(page, 'session must survive callback remount / reload').not.toHaveURL(
    /\/login(\/callback)?$/,
  );
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
  await expectJwtSession(page);
}

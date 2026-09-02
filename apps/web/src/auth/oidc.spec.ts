import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildGatewayRequest, isPatToken, TOKEN_STORAGE_KEY, tokenStore } from '../api/client';
import {
  beginAuthorization,
  callbackUri,
  completeAuthorization,
  isJwtAccessToken,
  keepSessionAfterCallbackError,
  OIDC_CLIENT_ID,
  OIDC_ISSUER,
  PKCE_STATE_KEY,
  PKCE_VERIFIER_KEY,
  readStoredAccessJwt,
  s256Challenge,
} from './oidc';

function memoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear() {
      map.clear();
    },
    getItem(key) {
      return map.has(key) ? (map.get(key) as string) : null;
    },
    key(index) {
      return [...map.keys()][index] ?? null;
    },
    removeItem(key) {
      map.delete(key);
    },
    setItem(key, value) {
      map.set(key, String(value));
    },
  };
}

const ISSUED_JWT =
  'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vfGFuYWx5c3QiLCJvcmdfaWQiOiJjN2UwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJyb2xlcyI6WyJvd25lciJdLCJhdWQiOiJjdGVtLWFwaSJ9.sig';
const ISSUED_PAT = 'ctem_pat_this-must-never-be-the-browser-session';

describe('browser OIDC login (public client + PKCE)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('login starts authorize with PKCE against the compose ctem realm', async () => {
    const storage = memoryStorage();
    const assigned: string[] = [];
    const href = await beginAuthorization({
      origin: 'http://localhost:3000',
      storage,
      assign: (url) => assigned.push(url),
    });

    const url = new URL(href);
    expect(url.origin + url.pathname).toBe(`${OIDC_ISSUER}/protocol/openid-connect/auth`);
    expect(url.searchParams.get('client_id')).toBe(OIDC_CLIENT_ID);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('scope')).toBe('openid');
    expect(url.searchParams.get('redirect_uri')).toBe(callbackUri('http://localhost:3000'));
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    const verifier = storage.getItem(PKCE_VERIFIER_KEY);
    expect(verifier).toBeTruthy();
    expect(isPatToken(verifier ?? '')).toBe(false);
    expect(url.searchParams.get('code_challenge')).toBe(await s256Challenge(verifier as string));
    expect(url.searchParams.get('state')).toBe(storage.getItem(PKCE_STATE_KEY));
    expect(assigned).toEqual([href]);
    expect(storage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it('callback stores the issued JWT not a PAT', async () => {
    const storage = memoryStorage();
    const href = await beginAuthorization({ origin: 'http://localhost:3000', storage });
    const authorize = new URL(href);
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      expect(String(input)).toBe(`${OIDC_ISSUER}/protocol/openid-connect/token`);
      expect(init?.method).toBe('POST');
      const body = new URLSearchParams(String(init?.body));
      expect(body.get('grant_type')).toBe('authorization_code');
      expect(body.get('client_id')).toBe(OIDC_CLIENT_ID);
      expect(body.get('code')).toBe('kc-auth-code');
      expect(body.get('code_verifier')).toBe(storage.getItem(PKCE_VERIFIER_KEY));
      expect(body.get('client_secret')).toBeNull();
      return new Response(
        JSON.stringify({
          access_token: ISSUED_JWT,
          id_token: 'eyJhbGciOiJub25lIn0.e30.',
          refresh_token: ISSUED_PAT,
          token_type: 'Bearer',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });

    const jwt = await completeAuthorization({
      search: `?code=kc-auth-code&state=${authorize.searchParams.get('state')}`,
      origin: 'http://localhost:3000',
      storage,
      fetch: fetchImpl,
    });

    expect(jwt).toBe(ISSUED_JWT);
    expect(isJwtAccessToken(jwt)).toBe(true);
    expect(isPatToken(jwt)).toBe(false);
    expect(tokenStore(storage).get()).toBe(ISSUED_JWT);
    expect(storage.getItem(TOKEN_STORAGE_KEY)).toBe(ISSUED_JWT);
    expect(storage.getItem(TOKEN_STORAGE_KEY)).not.toMatch(/ctem_pat_/);
    for (let i = 0; i < storage.length; i += 1) {
      const key = storage.key(i);
      const value = key ? storage.getItem(key) : '';
      expect(key ?? '').not.toMatch(/ctem_pat_/);
      expect(value ?? '').not.toMatch(/ctem_pat_/);
    }
    expect(storage.getItem(PKCE_VERIFIER_KEY)).toBeNull();
    expect(storage.getItem(PKCE_STATE_KEY)).toBeNull();
  });

  it('refuses to put a PAT from the token endpoint into sessionStorage', async () => {
    const storage = memoryStorage();
    const href = await beginAuthorization({ origin: 'http://localhost:3000', storage });
    const state = new URL(href).searchParams.get('state');
    const fetchImpl = vi.fn<typeof fetch>(
      async () =>
        new Response(JSON.stringify({ access_token: ISSUED_PAT }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );

    await expect(
      completeAuthorization({
        search: `?code=kc-auth-code&state=${state}`,
        origin: 'http://localhost:3000',
        storage,
        fetch: fetchImpl,
      }),
    ).rejects.toThrow(/access-token JWT|PAT/i);
    expect(storage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
    expect(tokenStore(storage).get()).toBeNull();
  });

  it('org still comes from the stored JWT; a client org selector is ignored', async () => {
    const storage = memoryStorage();
    const href = await beginAuthorization({ origin: 'http://localhost:3000', storage });
    const state = new URL(href).searchParams.get('state');
    const fetchImpl = vi.fn<typeof fetch>(
      async () =>
        new Response(JSON.stringify({ access_token: ISSUED_JWT }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    const jwt = await completeAuthorization({
      search: `?code=kc-auth-code&state=${state}`,
      origin: 'http://localhost:3000',
      storage,
      fetch: fetchImpl,
    });

    const req = buildGatewayRequest('/v1/session', {
      token: jwt,
      query: { limit: 1 },
    });
    expect(req.headers.authorization).toBe(`Bearer ${ISSUED_JWT}`);
    expect(req.url).toBe('/v1/session?limit=1');
    expect(req.url).not.toMatch(/org/i);
    expect(req.headers['x-ctem-org']).toBeUndefined();
    expect(() =>
      buildGatewayRequest('/v1/session', {
        token: jwt,
        query: { orgId: 'bbbbbbbb-2222-4333-8444-555566667777' },
      }),
    ).toThrow(/org selector/);
    expect(() =>
      buildGatewayRequest('/v1/findings', {
        token: jwt,
        query: { org_id: 'other-org' },
      }),
    ).toThrow(/org selector/);
  });
});

describe('human OIDC login path (not gateway PAT smoke)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function startPkce(storage: Storage): Promise<string> {
    const href = await beginAuthorization({ origin: 'http://localhost:3000', storage });
    const state = new URL(href).searchParams.get('state');
    return `?code=kc-auth-code&state=${state}`;
  }

  function tokenFetch(
    impl: (call: number) => Response | Promise<Response>,
  ): ReturnType<typeof vi.fn<typeof fetch>> {
    let calls = 0;
    return vi.fn<typeof fetch>(async () => {
      calls += 1;
      return impl(calls);
    });
  }

  it('two completeAuthorization calls with the same code do not leave the user logged out', async () => {
    const storage = memoryStorage();
    const search = await startPkce(storage);

    let releaseFirst: ((res: Response) => void) | undefined;
    const firstToken = new Promise<Response>((resolve) => {
      releaseFirst = resolve;
    });
    const fetchImpl = tokenFetch((call) => {
      if (call === 1) return firstToken;
      return new Response(
        JSON.stringify({ error: 'invalid_grant', error_description: 'Code not valid' }),
        { status: 400, headers: { 'content-type': 'application/json' } },
      );
    });

    const first = completeAuthorization({
      search,
      origin: 'http://localhost:3000',
      storage,
      fetch: fetchImpl,
    });
    const second = completeAuthorization({
      search,
      origin: 'http://localhost:3000',
      storage,
      fetch: fetchImpl,
    });
    releaseFirst!(
      new Response(JSON.stringify({ access_token: ISSUED_JWT }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );

    await expect(Promise.all([first, second])).resolves.toEqual([ISSUED_JWT, ISSUED_JWT]);
    expect(tokenStore(storage).get()).toBe(ISSUED_JWT);
    expect(readStoredAccessJwt(storage)).toBe(ISSUED_JWT);
    expect(isJwtAccessToken(tokenStore(storage).get() as string)).toBe(true);
    expect(keepSessionAfterCallbackError(storage)).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('skips a second exchange when a JWT is already stored', async () => {
    const storage = memoryStorage();
    const search = await startPkce(storage);
    const fetchImpl = tokenFetch(
      () =>
        new Response(JSON.stringify({ access_token: ISSUED_JWT }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );

    await completeAuthorization({
      search,
      origin: 'http://localhost:3000',
      storage,
      fetch: fetchImpl,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(tokenStore(storage).get()).toBe(ISSUED_JWT);

    const skipped = await completeAuthorization({
      search,
      origin: 'http://localhost:3000',
      storage,
      fetch: fetchImpl,
    });
    expect(skipped).toBe(ISSUED_JWT);
    expect(tokenStore(storage).get()).toBe(ISSUED_JWT);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('does not clear a valid JWT on a later token 400', async () => {
    const storage = memoryStorage();
    const search = await startPkce(storage);
    await completeAuthorization({
      search,
      origin: 'http://localhost:3000',
      storage,
      fetch: tokenFetch(
        () =>
          new Response(JSON.stringify({ access_token: ISSUED_JWT }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      ),
    });
    expect(tokenStore(storage).get()).toBe(ISSUED_JWT);

    const replay = await startPkce(storage);
    const fetch400 = tokenFetch(
      () =>
        new Response(
          JSON.stringify({ error: 'invalid_grant', error_description: 'Code not valid' }),
          { status: 400, headers: { 'content-type': 'application/json' } },
        ),
    );

    await expect(
      completeAuthorization({
        search: replay,
        origin: 'http://localhost:3000',
        storage,
        fetch: fetch400,
      }),
    ).resolves.toBe(ISSUED_JWT);
    expect(fetch400).not.toHaveBeenCalled();
    expect(tokenStore(storage).get()).toBe(ISSUED_JWT);

    expect(keepSessionAfterCallbackError(storage)).toBe(true);
    if (!keepSessionAfterCallbackError(storage)) tokenStore(storage).clear();
    expect(tokenStore(storage).get()).toBe(ISSUED_JWT);
    expect(isPatToken(tokenStore(storage).get() as string)).toBe(false);
  });
});

describe('login UI has no password field and no PAT in sessionStorage', () => {
  const login = readFileSync(resolve('apps/web/src/pages/LoginPage.tsx'), 'utf8');
  const callback = readFileSync(resolve('apps/web/src/pages/CallbackPage.tsx'), 'utf8');
  const app = readFileSync(resolve('apps/web/src/App.tsx'), 'utf8');

  it('has no password field, JWT paste, or PAT prompt', () => {
    for (const source of [login, callback]) {
      expect(source).not.toMatch(/type=["']password["']/);
      expect(source).not.toMatch(/<textarea/);
      expect(source).not.toMatch(/placeholder="eyJ/);
      expect(source).not.toMatch(/Paste a JWT/);
      expect(source).not.toMatch(/\bPAT\b/);
      expect(source).not.toMatch(/ctem_pat_/);
      expect(source).not.toMatch(/personal access/i);
      expect(source).not.toMatch(/machine token/i);
      expect(source).not.toMatch(/<input/i);
    }
    expect(login).toMatch(/Sign in with Keycloak/);
    expect(login).toMatch(/beginAuthorization/);
    expect(callback).toMatch(/completeAuthorization/);
    expect(callback).toMatch(/issued access-token JWT/);
    expect(callback).toMatch(/history\.replaceState/);
    expect(callback).toMatch(/keepSessionAfterCallbackError/);
    expect(callback).not.toMatch(/catch \(err\) \{\s*tokenStore\(\)\.clear\(\)/);
    expect(app).toMatch(/path="\/login\/callback"/);
  });
});

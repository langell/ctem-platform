/**
 * Browser OIDC for apps/web. Public client + PKCE against compose Keycloak
 * realm `ctem`. The session is the issued access-token JWT; the gateway still
 * verifies it via JWKS. Machine PATs never live in the browser.
 */
import { TOKEN_STORAGE_KEY, isPatToken, tokenStore } from '../api/client';

export const OIDC_ISSUER = 'http://localhost:8080/realms/ctem';
export const OIDC_CLIENT_ID = 'ctem-web';
export const OIDC_CALLBACK_PATH = '/login/callback';
export const PKCE_VERIFIER_KEY = 'ctem.oidc.code_verifier';
export const PKCE_STATE_KEY = 'ctem.oidc.state';

export function isJwtAccessToken(token: string): boolean {
  const value = token.trim();
  if (!value || isPatToken(value)) return false;
  const parts = value.split('.');
  return parts.length === 3 && parts.every((part) => part.length > 0);
}

export function callbackUri(origin: string): string {
  return `${origin.replace(/\/$/, '')}${OIDC_CALLBACK_PATH}`;
}

function defaultStorage(): Storage | undefined {
  return typeof sessionStorage === 'undefined' ? undefined : sessionStorage;
}

function requireStorage(storage: Storage | undefined = defaultStorage()): Storage {
  if (!storage) throw new Error('Browser session storage is required for PKCE login');
  return storage;
}

function toBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function randomUrlToken(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

export async function s256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return toBase64Url(new Uint8Array(digest));
}

export interface BeginAuthorizationOptions {
  origin: string;
  storage?: Storage;
  assign?: (url: string) => void;
}

/**
 * Start the authorization-code + PKCE redirect to compose Keycloak.
 * Stores only the verifier and state — never a PAT or password.
 */
export async function beginAuthorization(options: BeginAuthorizationOptions): Promise<string> {
  const storage = requireStorage(options.storage);
  const verifier = randomUrlToken();
  const state = randomUrlToken(16);
  const challenge = await s256Challenge(verifier);
  storage.setItem(PKCE_VERIFIER_KEY, verifier);
  storage.setItem(PKCE_STATE_KEY, state);

  const url = new URL(`${OIDC_ISSUER}/protocol/openid-connect/auth`);
  url.searchParams.set('client_id', OIDC_CLIENT_ID);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid');
  url.searchParams.set('redirect_uri', callbackUri(options.origin));
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', state);

  const href = url.toString();
  options.assign?.(href);
  return href;
}

export interface CompleteAuthorizationOptions {
  search: string;
  origin: string;
  storage?: Storage;
  fetch?: typeof fetch;
}

/** One in-flight exchange so React Strict Mode cannot POST the same code twice. */
let inflightExchange: Promise<string> | undefined;

export function readStoredAccessJwt(
  storage: Storage | undefined = defaultStorage(),
): string | null {
  const value = tokenStore(storage).get();
  if (!value || !isJwtAccessToken(value) || isPatToken(value)) return null;
  return value;
}

/** A later token 400 (Strict Mode remount) must not wipe a JWT already stored. */
export function keepSessionAfterCallbackError(
  storage: Storage | undefined = defaultStorage(),
): boolean {
  return readStoredAccessJwt(storage) !== null;
}

/**
 * Exchange the Keycloak authorization code for the issued access-token JWT
 * and persist that JWT as the gateway session. Refuses a PAT in every case.
 *
 * The authorization code is single-use. Vite/React Strict Mode remounts the
 * callback and would otherwise POST it twice; the second call is 400 and must
 * not log the user out.
 */
export async function completeAuthorization(
  options: CompleteAuthorizationOptions,
): Promise<string> {
  const storage = requireStorage(options.storage);
  const existing = readStoredAccessJwt(storage);
  if (existing) return existing;
  if (inflightExchange) return inflightExchange;

  inflightExchange = exchangeAuthorizationCode(options, storage).finally(() => {
    inflightExchange = undefined;
  });
  return inflightExchange;
}

async function exchangeAuthorizationCode(
  options: CompleteAuthorizationOptions,
  storage: Storage,
): Promise<string> {
  const existing = readStoredAccessJwt(storage);
  if (existing) return existing;

  const params = new URLSearchParams(
    options.search.startsWith('?') ? options.search.slice(1) : options.search,
  );
  const idpError = params.get('error');
  if (idpError) {
    const kept = readStoredAccessJwt(storage);
    if (kept) return kept;
    clearPkce(storage);
    throw new Error(params.get('error_description') || `Keycloak returned ${idpError}`);
  }

  const code = params.get('code');
  const returnedState = params.get('state');
  const expectedState = storage.getItem(PKCE_STATE_KEY);
  const verifier = storage.getItem(PKCE_VERIFIER_KEY);
  if (!code || !returnedState || !expectedState || returnedState !== expectedState || !verifier) {
    const kept = readStoredAccessJwt(storage);
    if (kept) return kept;
    clearPkce(storage);
    throw new Error('Login callback is missing a valid authorization code.');
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: OIDC_CLIENT_ID,
    code,
    redirect_uri: callbackUri(options.origin),
    code_verifier: verifier,
  });

  const fetchImpl = options.fetch ?? fetch;
  const res = await fetchImpl(`${OIDC_ISSUER}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body,
  });
  const payload = (await res.json().catch(() => null)) as {
    access_token?: string;
    error?: string;
    error_description?: string;
  } | null;
  clearPkce(storage);
  if (!res.ok || !payload?.access_token) {
    const kept = readStoredAccessJwt(storage);
    if (kept) return kept;
    throw new Error(
      payload?.error_description || payload?.error || 'Keycloak did not issue an access token.',
    );
  }

  const jwt = payload.access_token.trim();
  if (!isJwtAccessToken(jwt)) {
    throw new Error('Keycloak response was not an access-token JWT.');
  }

  tokenStore(storage).set(jwt);
  const stored = storage.getItem(TOKEN_STORAGE_KEY);
  if (!stored || isPatToken(stored)) {
    tokenStore(storage).clear();
    throw new Error('Refusing to store a PAT in the browser session');
  }
  return jwt;
}

function clearPkce(storage: Storage): void {
  storage.removeItem(PKCE_VERIFIER_KEY);
  storage.removeItem(PKCE_STATE_KEY);
}

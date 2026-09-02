import { createPrivateKey, createSign } from 'node:crypto';
import type { GcpCredentials } from './credentials';
import { normalizeGcpPrivateKey } from './credentials';
import { allowlistedGcpUrl, GCP_TOKEN_URL } from './gcp.egress';

/** Inventory-only scopes. Not cloud-platform, not write. */
export const GCP_OAUTH_SCOPE = [
  'https://www.googleapis.com/auth/compute.readonly',
  'https://www.googleapis.com/auth/devstorage.read_only',
].join(' ');

/**
 * RS256 service-account JWT. Audience is hardcoded to Google's token URL —
 * never a tenant- or JSON-supplied token_uri.
 */
export function signServiceAccountJwt(creds: GcpCredentials, now = new Date()): string {
  const header = { alg: 'RS256', typ: 'JWT' };
  const iat = Math.floor(now.getTime() / 1000);
  const payload = {
    iss: creds.clientEmail,
    scope: GCP_OAUTH_SCOPE,
    aud: GCP_TOKEN_URL,
    iat,
    exp: iat + 3600,
  };
  const encode = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const unsigned = `${encode(header)}.${encode(payload)}`;
  const sign = createSign('RSA-SHA256');
  sign.update(unsigned);
  const key = createPrivateKey(normalizeGcpPrivateKey(creds.privateKey));
  return `${unsigned}.${sign.sign(key, 'base64url')}`;
}

/**
 * Exchange the assertion at oauth2.googleapis.com only. Keys never leave
 * the Google host allowlist.
 */
export async function exchangeGcpAccessToken(creds: GcpCredentials): Promise<string> {
  const assertion = signServiceAccountJwt(creds);
  const url = allowlistedGcpUrl(GCP_TOKEN_URL);
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion,
  }).toString();
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) {
    throw new Error(`GCP token API returned ${res.status}`);
  }
  const json = (await res.json()) as { access_token?: unknown };
  if (typeof json.access_token !== 'string' || json.access_token.length === 0) {
    throw new Error('GCP token API did not return an access_token');
  }
  return json.access_token;
}

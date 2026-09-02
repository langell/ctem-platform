import { createVerify, generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { GCP_TOKEN_URL } from './gcp.egress';
import { exchangeGcpAccessToken, GCP_OAUTH_SCOPE, signServiceAccountJwt } from './gcp.jwt';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const creds = {
  clientEmail: 'ctem-discovery@acme-prod.iam.gserviceaccount.com',
  privateKey: pem,
};

function decodeJwt(jwt: string): { header: unknown; payload: Record<string, unknown> } {
  const [h, p, s] = jwt.split('.');
  expect(h && p && s).toBeTruthy();
  const verify = createVerify('RSA-SHA256');
  verify.update(`${h}.${p}`);
  expect(verify.verify(publicKey, s!, 'base64url')).toBe(true);
  return {
    header: JSON.parse(Buffer.from(h!, 'base64url').toString()),
    payload: JSON.parse(Buffer.from(p!, 'base64url').toString()) as Record<string, unknown>,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('signServiceAccountJwt', () => {
  it('signs RS256 with audience hardcoded to Google token host', () => {
    const now = new Date('2026-09-02T00:00:00.000Z');
    const jwt = signServiceAccountJwt(creds, now);
    const { header, payload } = decodeJwt(jwt);
    expect(header).toEqual({ alg: 'RS256', typ: 'JWT' });
    expect(payload.iss).toBe(creds.clientEmail);
    expect(payload.aud).toBe(GCP_TOKEN_URL);
    expect(payload.aud).toBe('https://oauth2.googleapis.com/token');
    expect(payload.scope).toBe(GCP_OAUTH_SCOPE);
    const iat = Math.floor(now.getTime() / 1000);
    expect(payload.iat).toBe(iat);
    expect(payload.exp).toBe(iat + 3600);
  });
});

describe('exchangeGcpAccessToken', () => {
  it('posts the assertion only to oauth2.googleapis.com', async () => {
    const fetchFn = vi.fn(async () =>
      new Response(JSON.stringify({ access_token: 'ya29.test' }), { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchFn);
    await expect(exchangeGcpAccessToken(creds)).resolves.toBe('ya29.test');
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url, init] = fetchFn.mock.calls[0]!;
    expect(String(url)).toBe('https://oauth2.googleapis.com/token');
    expect(new URL(String(url)).hostname).toBe('oauth2.googleapis.com');
    const body = String(init?.body ?? '');
    expect(body).toContain('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer');
    expect(body).toContain('assertion=');
    expect(String(url)).not.toContain('evil');
  });

  it('fails closed when the token API does not return an access_token', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 })),
    );
    await expect(exchangeGcpAccessToken(creds)).rejects.toThrow(/400/);
  });
});

import { afterEach, describe, expect, it, vi } from 'vitest';
import { AZURE_TOKEN_SCOPE } from './azure.egress';
import { exchangeAzureAccessToken } from './azure.token';

const TENANT = '22222222-2222-2222-2222-222222222222';
const creds = {
  tenantId: TENANT,
  clientId: '33333333-3333-3333-3333-333333333333',
  clientSecret: 'super-secret',
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('exchangeAzureAccessToken', () => {
  it('posts client credentials only to login.microsoftonline.com', async () => {
    const fetchFn = vi.fn(
      async () => new Response(JSON.stringify({ access_token: 'eyJhbGciOiJSUzI1NiJ9.test' }), { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchFn);
    await expect(exchangeAzureAccessToken(creds)).resolves.toBe('eyJhbGciOiJSUzI1NiJ9.test');
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url, init] = fetchFn.mock.calls[0]!;
    expect(String(url)).toBe(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`);
    expect(new URL(String(url)).hostname).toBe('login.microsoftonline.com');
    expect(init?.method).toBe('POST');
    const body = String(init?.body ?? '');
    expect(body).toContain('grant_type=client_credentials');
    expect(body).toContain(`scope=${encodeURIComponent(AZURE_TOKEN_SCOPE)}`);
    expect(body).toContain(`client_id=${creds.clientId}`);
    expect(body).toContain('client_secret=super-secret');
    expect(AZURE_TOKEN_SCOPE).toBe('https://management.azure.com/.default');
    expect(String(url)).not.toContain('evil');
  });

  it('fails closed when the token API does not return an access_token', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ error: 'invalid_client' }), { status: 400 })),
    );
    await expect(exchangeAzureAccessToken(creds)).rejects.toThrow(/400/);
  });

  it('fails closed when the token body omits access_token', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ token_type: 'Bearer' }), { status: 200 })),
    );
    await expect(exchangeAzureAccessToken(creds)).rejects.toThrow(/access_token/);
  });
});

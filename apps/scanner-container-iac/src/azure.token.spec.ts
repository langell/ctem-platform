import { afterEach, describe, expect, it, vi } from 'vitest';
import { ACR_AAD_SCOPE, AZURE_LOGIN_HOST, allowlistedAzureTokenUrl, azureTokenUrl } from './azure.egress';
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

describe('allowlistedAzureTokenUrl', () => {
  it('accepts login.microsoftonline.com /{tenant}/oauth2/v2.0/token over https/443', () => {
    expect(allowlistedAzureTokenUrl(`https://${AZURE_LOGIN_HOST}/${TENANT}/oauth2/v2.0/token`)).toBe(
      `https://${AZURE_LOGIN_HOST}/${TENANT}/oauth2/v2.0/token`,
    );
    expect(azureTokenUrl(TENANT)).toBe(`https://${AZURE_LOGIN_HOST}/${TENANT}/oauth2/v2.0/token`);
  });

  it('refuses ACR docker, ARM, suffix confusion, and other Azure hosts', () => {
    expect(() => allowlistedAzureTokenUrl('https://acmeprod.azurecr.io/oauth2/token')).toThrow(
      /only login\.microsoftonline\.com/,
    );
    expect(() =>
      allowlistedAzureTokenUrl(`https://${AZURE_LOGIN_HOST}.evil.example/${TENANT}/oauth2/v2.0/token`),
    ).toThrow(/only login\.microsoftonline\.com/);
    expect(() =>
      allowlistedAzureTokenUrl(`https://management.azure.com/${TENANT}/oauth2/v2.0/token`),
    ).toThrow(/only login\.microsoftonline\.com/);
    expect(() =>
      allowlistedAzureTokenUrl(`https://${AZURE_LOGIN_HOST}/${TENANT}/oauth2/v1.0/token`),
    ).toThrow(/oauth2\/v2\.0\/token/);
    expect(() => azureTokenUrl('https://evil.example')).toThrow(/tenant/);
  });
});

describe('exchangeAzureAccessToken', () => {
  it('posts client credentials only to login.microsoftonline.com with the ACR audience', async () => {
    const fetchFn = vi.fn(
      async () =>
        new Response(JSON.stringify({ access_token: 'eyJhbGciOiJSUzI1NiJ9.acr' }), { status: 200 }),
    );
    await expect(
      exchangeAzureAccessToken(creds, fetchFn as unknown as typeof fetch),
    ).resolves.toBe('eyJhbGciOiJSUzI1NiJ9.acr');
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url, init] = fetchFn.mock.calls[0]!;
    expect(String(url)).toBe(`https://${AZURE_LOGIN_HOST}/${TENANT}/oauth2/v2.0/token`);
    expect(new URL(String(url)).hostname).toBe(AZURE_LOGIN_HOST);
    expect(init?.method).toBe('POST');
    const body = String(init?.body ?? '');
    expect(body).toContain('grant_type=client_credentials');
    expect(body).toContain(`scope=${encodeURIComponent(ACR_AAD_SCOPE)}`);
    expect(body).toContain(`client_id=${creds.clientId}`);
    expect(body).toContain('client_secret=super-secret');
    expect(ACR_AAD_SCOPE).toBe('https://containerregistry.azure.net/.default');
    expect(String(url)).not.toContain('azurecr.io');
  });

  it('refuses a token scope that is not the ACR AAD audience', async () => {
    const fetchFn = vi.fn();
    await expect(
      exchangeAzureAccessToken(
        creds,
        fetchFn as unknown as typeof fetch,
        'https://management.azure.com/.default',
      ),
    ).rejects.toThrow(/not allowlisted/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when the token API does not return an access_token', async () => {
    const fetchFn = vi.fn(
      async () => new Response(JSON.stringify({ error: 'invalid_client' }), { status: 400 }),
    );
    await expect(
      exchangeAzureAccessToken(creds, fetchFn as unknown as typeof fetch),
    ).rejects.toThrow(/400/);
  });

  it('fails closed when the token body omits access_token', async () => {
    const fetchFn = vi.fn(
      async () => new Response(JSON.stringify({ token_type: 'Bearer' }), { status: 200 }),
    );
    await expect(
      exchangeAzureAccessToken(creds, fetchFn as unknown as typeof fetch),
    ).rejects.toThrow(/access_token/);
  });
});

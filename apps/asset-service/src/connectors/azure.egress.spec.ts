import { describe, expect, it } from 'vitest';
import {
  AZURE_ARM_HOST,
  AZURE_LOGIN_HOST,
  allowlistedAzureArmUrl,
  allowlistedAzureTokenUrl,
  azureArmListUrl,
  azureTokenUrl,
  isAzureArmHost,
  isAzureLoginHost,
  refuseTenantWritableEndpoint,
} from './azure.egress';

const SUB = '11111111-1111-1111-1111-111111111111';
const TENANT = '22222222-2222-2222-2222-222222222222';

describe('allowlistedAzureTokenUrl / allowlistedAzureArmUrl', () => {
  it('accepts the hardcoded Azure login and ARM hosts', () => {
    expect(allowlistedAzureTokenUrl(`https://${AZURE_LOGIN_HOST}/${TENANT}/oauth2/v2.0/token`)).toBe(
      `https://${AZURE_LOGIN_HOST}/${TENANT}/oauth2/v2.0/token`,
    );
    expect(
      allowlistedAzureArmUrl(
        `https://${AZURE_ARM_HOST}/subscriptions/${SUB}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01`,
      ),
    ).toBe(
      `https://${AZURE_ARM_HOST}/subscriptions/${SUB}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01`,
    );
  });

  it('refuses a tenant-writable host', () => {
    expect(() => allowlistedAzureArmUrl('https://evil.example/azure')).toThrow(/only management\.azure\.com/);
    expect(() => allowlistedAzureTokenUrl('https://evil.example/token')).toThrow(
      /only login\.microsoftonline\.com/,
    );
  });

  it('refuses suffix-confusion, lookalike, and out-of-scope Azure hosts', () => {
    expect(() => allowlistedAzureArmUrl('https://management.azure.com.evil.example/')).toThrow(
      /only management\.azure\.com/,
    );
    expect(() => allowlistedAzureArmUrl('https://evilmanagement.azure.com/')).toThrow(
      /only management\.azure\.com/,
    );
    expect(() => allowlistedAzureArmUrl('https://management.azure.com.evil.example/subscriptions/x')).toThrow(
      /only management\.azure\.com/,
    );
    expect(() => allowlistedAzureArmUrl('https://contoso.blob.core.windows.net/logs')).toThrow(
      /only management\.azure\.com/,
    );
    expect(() => allowlistedAzureArmUrl('https://graph.microsoft.com/v1.0/users')).toThrow(
      /only management\.azure\.com/,
    );
    expect(() => allowlistedAzureArmUrl('https://management.usgovcloudapi.net/')).toThrow(
      /only management\.azure\.com/,
    );
    expect(() => allowlistedAzureTokenUrl('https://login.microsoftonline.us/token')).toThrow(
      /only login\.microsoftonline\.com/,
    );
  });

  it('refuses http, userinfo, and non-default ports', () => {
    expect(() => allowlistedAzureArmUrl('http://management.azure.com/')).toThrow(/non-https/);
    expect(() => allowlistedAzureArmUrl('https://user:pass@management.azure.com/')).toThrow(/userinfo/);
    expect(() => allowlistedAzureArmUrl('https://management.azure.com:8443/')).toThrow(/port/);
    expect(() => allowlistedAzureTokenUrl('http://login.microsoftonline.com/token')).toThrow(/non-https/);
    expect(() => allowlistedAzureTokenUrl('https://user:pass@login.microsoftonline.com/token')).toThrow(
      /userinfo/,
    );
  });
});

describe('isAzureLoginHost / isAzureArmHost', () => {
  it('accepts only the exact allowlisted hosts', () => {
    expect(isAzureLoginHost('login.microsoftonline.com')).toBe(true);
    expect(isAzureArmHost('management.azure.com')).toBe(true);
    expect(isAzureLoginHost('login.microsoftonline.com.')).toBe(true);
    expect(isAzureArmHost('MANAGEMENT.AZURE.COM')).toBe(true);
    expect(isAzureArmHost('evil.example')).toBe(false);
    expect(isAzureArmHost('management.azure.com.evil.example')).toBe(false);
    expect(isAzureArmHost('blob.core.windows.net')).toBe(false);
    expect(isAzureLoginHost('login.microsoftonline.us')).toBe(false);
  });
});

describe('azureTokenUrl / azureArmListUrl', () => {
  it('derives login and ARM hosts from identifiers, never a tenant host', () => {
    expect(azureTokenUrl(TENANT)).toBe(
      `https://${AZURE_LOGIN_HOST}/${TENANT}/oauth2/v2.0/token`,
    );
    expect(azureArmListUrl(SUB, '/providers/Microsoft.Compute/virtualMachines', '2024-07-01')).toBe(
      `https://${AZURE_ARM_HOST}/subscriptions/${SUB}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01`,
    );
  });

  it('refuses a subscriptionId that is not an Azure subscription identifier', () => {
    expect(() =>
      azureArmListUrl('acme-prod.evil.example', '/providers/Microsoft.Compute/virtualMachines', '2024-07-01'),
    ).toThrow(/subscriptionId/);
    expect(() =>
      azureArmListUrl('https://evil.example', '/providers/Microsoft.Compute/virtualMachines', '2024-07-01'),
    ).toThrow(/subscriptionId/);
  });

  it('refuses a tenantId that is not an Azure tenant identifier', () => {
    expect(() => azureTokenUrl('https://evil.example')).toThrow(/tenantId/);
    expect(() => azureTokenUrl('contoso.onmicrosoft.com')).toThrow(/tenantId/);
  });
});

describe('refuseTenantWritableEndpoint', () => {
  it('allows a subscriptionId-only config', () => {
    expect(() => refuseTenantWritableEndpoint({ subscriptionId: SUB })).not.toThrow();
  });

  it('refuses tenant-writable endpoint keys', () => {
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, endpoint: 'https://evil.example' }),
    ).toThrow(/tenant-writable Azure endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, apiUrl: 'https://evil.example/arm' }),
    ).toThrow(/tenant-writable Azure endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, host: 'evil.example' }),
    ).toThrow(/tenant-writable Azure endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, loginUrl: 'https://evil.example/login' }),
    ).toThrow(/tenant-writable Azure endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, tokenUrl: 'https://evil.example/token' }),
    ).toThrow(/tenant-writable Azure endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, armEndpoint: 'https://evil.example/arm' }),
    ).toThrow(/tenant-writable Azure endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, resourceManagerUrl: 'https://evil.example' }),
    ).toThrow(/tenant-writable Azure endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, cloud: 'AzureChinaCloud' }),
    ).toThrow(/tenant-writable Azure endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, environment: 'AzureUSGovernment' }),
    ).toThrow(/tenant-writable Azure endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, authority: 'https://login.evil.example' }),
    ).toThrow(/tenant-writable Azure endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, baseUrl: 'https://evil.example' }),
    ).toThrow(/tenant-writable Azure endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, url: 'https://evil.example' }),
    ).toThrow(/tenant-writable Azure endpoint/);
  });

  it('refuses a subscriptionId that is itself a URL', () => {
    expect(() => refuseTenantWritableEndpoint({ subscriptionId: 'https://evil.example' })).toThrow(
      /tenant-writable Azure endpoint/,
    );
  });
});

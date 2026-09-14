import { describe, expect, it } from 'vitest';
import {
  TENANT_ENDPOINT_KEYS,
  acrArmRegistriesUrl,
  acrCatalogUrl,
  acrManifestsUrl,
  acrOauthExchangeUrl,
  allowlistedAcrDataUrl,
  allowlistedAcrNextUrl,
  assertAcrLoginServer,
  isAcrLoginServerHost,
  pinAcrLoginServer,
  refuseTenantWritableEndpoint,
} from './acr.egress';

const SUB = '11111111-1111-1111-1111-111111111111';
const LOGIN = 'acmeprod.azurecr.io';

describe('allowlistedAcrDataUrl / isAcrLoginServerHost', () => {
  it('accepts the ARM-derived {name}.azurecr.io loginServer', () => {
    expect(allowlistedAcrDataUrl(`https://${LOGIN}/acr/v1/_catalog`, LOGIN)).toBe(
      `https://${LOGIN}/acr/v1/_catalog`,
    );
    expect(isAcrLoginServerHost(LOGIN)).toBe(true);
    expect(isAcrLoginServerHost('ACMEPROD.AZURECR.IO')).toBe(true);
    expect(pinAcrLoginServer(LOGIN)).toBe(LOGIN);
  });

  it('refuses a different azurecr.io registry than the ARM pin', () => {
    expect(() =>
      allowlistedAcrDataUrl('https://evilreg.azurecr.io/acr/v1/_catalog', LOGIN),
    ).toThrow(/ARM-derived acmeprod\.azurecr\.io/);
  });

  it('refuses suffix-confusion, data endpoints, China/gov, and lookalikes', () => {
    expect(isAcrLoginServerHost('acmeprod.azurecr.io.evil.example')).toBe(false);
    expect(isAcrLoginServerHost('acmeprod.eastus.data.azurecr.io')).toBe(false);
    expect(isAcrLoginServerHost('acmeprod.azurecr.cn')).toBe(false);
    expect(isAcrLoginServerHost('acmeprod.azurecr.us')).toBe(false);
    expect(isAcrLoginServerHost('azurecr.io')).toBe(false);
    expect(isAcrLoginServerHost('notazurecr.io')).toBe(false);
    expect(() =>
      allowlistedAcrDataUrl('https://acmeprod.azurecr.io.evil.example/acr/v1/_catalog', LOGIN),
    ).toThrow(/only the ARM-derived|only \{name\}\.azurecr\.io/);
    expect(() => allowlistedAcrDataUrl('https://evil.example/acr', LOGIN)).toThrow(
      /ARM-derived acmeprod\.azurecr\.io/,
    );
    expect(() =>
      allowlistedAcrDataUrl('https://acmeprod.azurecr.cn/acr/v1/_catalog', LOGIN),
    ).toThrow(/ARM-derived|azurecr\.io/);
  });

  it('refuses http, userinfo, and non-default ports', () => {
    expect(() => allowlistedAcrDataUrl(`http://${LOGIN}/acr/v1/_catalog`, LOGIN)).toThrow(
      /non-https/,
    );
    expect(() =>
      allowlistedAcrDataUrl(`https://user:pass@${LOGIN}/acr/v1/_catalog`, LOGIN),
    ).toThrow(/userinfo/);
    expect(() => allowlistedAcrDataUrl(`https://${LOGIN}:8443/acr/v1/_catalog`, LOGIN)).toThrow(
      /port/,
    );
  });
});

describe('assertAcrLoginServer', () => {
  it('pins ARM loginServer to {registryName}.azurecr.io', () => {
    expect(assertAcrLoginServer('AcmeProd', LOGIN)).toBe(LOGIN);
    expect(assertAcrLoginServer('acmeprod', `https://${LOGIN}`)).toBe(LOGIN);
  });

  it("refuses a loginServer that is not the registry's own azurecr.io host", () => {
    expect(() => assertAcrLoginServer('acmeprod', 'acmeprod.azurecr.io.evil.example')).toThrow(
      /ARM-derived acmeprod\.azurecr\.io/,
    );
    expect(() => assertAcrLoginServer('acmeprod', 'otherreg.azurecr.io')).toThrow(
      /ARM-derived acmeprod\.azurecr\.io/,
    );
    expect(() => assertAcrLoginServer('acmeprod', 'acmeprod.azurecr.cn')).toThrow(
      /ARM-derived acmeprod\.azurecr\.io/,
    );
  });
});

describe('acr catalog / manifests / ARM URL builders', () => {
  it('builds list URLs on the pinned loginServer and ARM, never a tenant host', () => {
    expect(acrCatalogUrl(LOGIN)).toBe(`https://${LOGIN}/acr/v1/_catalog?n=100`);
    expect(acrManifestsUrl(LOGIN, 'payments-api')).toBe(
      `https://${LOGIN}/acr/v1/payments-api/_manifests?n=100`,
    );
    expect(acrManifestsUrl(LOGIN, 'team/api')).toBe(
      `https://${LOGIN}/acr/v1/team/api/_manifests?n=100`,
    );
    expect(acrOauthExchangeUrl(LOGIN)).toBe(`https://${LOGIN}/oauth2/exchange`);
    expect(acrArmRegistriesUrl(SUB)).toBe(
      `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.ContainerRegistry/registries?api-version=2023-07-01`,
    );
    expect(acrArmRegistriesUrl(SUB, 'rg-prod')).toBe(
      `https://management.azure.com/subscriptions/${SUB}/resourceGroups/rg-prod/providers/Microsoft.ContainerRegistry/registries?api-version=2023-07-01`,
    );
  });

  it('refuses a subscriptionId / resourceGroup / repository that is not an identifier', () => {
    expect(() => acrArmRegistriesUrl('acme-prod.evil.example')).toThrow(/subscriptionId/);
    expect(() => acrArmRegistriesUrl('https://evil.example')).toThrow(/subscriptionId/);
    expect(() => acrArmRegistriesUrl(SUB, 'https://evil.example')).toThrow(/resourceGroup/);
    expect(() => acrManifestsUrl(LOGIN, 'https://evil.example/app')).toThrow(/repository/);
  });

  it('resolves relative Link rel=next onto the pinned loginServer', () => {
    expect(allowlistedAcrNextUrl('/acr/v1/_catalog?last=foo&n=100', LOGIN)).toBe(
      `https://${LOGIN}/acr/v1/_catalog?last=foo&n=100`,
    );
    expect(allowlistedAcrNextUrl(`https://${LOGIN}/acr/v1/_catalog?last=foo&n=100`, LOGIN)).toBe(
      `https://${LOGIN}/acr/v1/_catalog?last=foo&n=100`,
    );
    expect(() =>
      allowlistedAcrNextUrl('https://evilreg.azurecr.io/acr/v1/_catalog?last=exfil', LOGIN),
    ).toThrow(/ARM-derived acmeprod\.azurecr\.io/);
    expect(() => allowlistedAcrNextUrl('https://evil.example/exfil', LOGIN)).toThrow(
      /ARM-derived acmeprod\.azurecr\.io/,
    );
  });
});

describe('refuseTenantWritableEndpoint', () => {
  it('allows a subscriptionId-only config', () => {
    expect(() => refuseTenantWritableEndpoint({ subscriptionId: SUB })).not.toThrow();
    expect(() =>
      refuseTenantWritableEndpoint({
        subscriptionId: SUB,
        resourceGroup: 'rg-prod',
        registry: 'acmeprod',
      }),
    ).not.toThrow();
  });

  it('refuses tenant-writable endpoint keys including registry URL / loginServer', () => {
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, endpoint: 'https://evil.example' }),
    ).toThrow(/tenant-writable ACR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        subscriptionId: SUB,
        loginServer: 'acmeprod.azurecr.io',
      }),
    ).toThrow(/tenant-writable ACR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        subscriptionId: SUB,
        registryUrl: 'https://acmeprod.azurecr.io',
      }),
    ).toThrow(/tenant-writable ACR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        subscriptionId: SUB,
        acrUrl: 'https://acmeprod.azurecr.io/v2/',
      }),
    ).toThrow(/tenant-writable ACR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ subscriptionId: SUB, host: 'acmeprod.azurecr.io' }),
    ).toThrow(/tenant-writable ACR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        subscriptionId: SUB,
        authority: 'https://login.microsoftonline.com.evil.example',
      }),
    ).toThrow(/tenant-writable ACR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        subscriptionId: SUB,
        cloud: 'AzureChinaCloud',
      }),
    ).toThrow(/tenant-writable ACR endpoint/);
    expect(TENANT_ENDPOINT_KEYS).toContain('loginServer');
    expect(TENANT_ENDPOINT_KEYS).toContain('registryUrl');
    expect(TENANT_ENDPOINT_KEYS).not.toContain('registry');
  });

  it('refuses EXTRA_*_HOST_KEYS', () => {
    expect(() =>
      refuseTenantWritableEndpoint({
        subscriptionId: SUB,
        EXTRA_ACR_HOST_KEYS: ['evil.example'],
      }),
    ).toThrow(/tenant-writable ACR endpoint/);
  });

  it('refuses a subscriptionId / resourceGroup / registry that is itself a URL', () => {
    expect(() => refuseTenantWritableEndpoint({ subscriptionId: 'https://evil.example' })).toThrow(
      /tenant-writable ACR endpoint/,
    );
    expect(() =>
      refuseTenantWritableEndpoint({
        subscriptionId: SUB,
        resourceGroup: 'https://management.azure.com',
      }),
    ).toThrow(/tenant-writable ACR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        subscriptionId: SUB,
        registry: 'https://acmeprod.azurecr.io',
      }),
    ).toThrow(/tenant-writable ACR endpoint/);
  });
});

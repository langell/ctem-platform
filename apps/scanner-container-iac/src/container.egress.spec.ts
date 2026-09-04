import { describe, expect, it } from 'vitest';
import {
  GHCR_REGISTRY_HOST,
  allowlistedGhcrBlobRedirect,
  allowlistedGhcrUrl,
  ghcrBlobUrl,
  ghcrManifestUrl,
  ghcrTokenUrl,
  isGhcrRegistryHost,
  refuseTenantWritableRegistry,
} from './container.egress';

const DIGEST = `sha256:${'a'.repeat(64)}`;

describe('allowlistedGhcrUrl', () => {
  it('accepts ghcr.io over https/443 for /v2 and /token', () => {
    expect(allowlistedGhcrUrl(`https://ghcr.io/v2/acme/app/manifests/${DIGEST}`)).toBe(
      `https://ghcr.io/v2/acme/app/manifests/${DIGEST}`,
    );
    expect(allowlistedGhcrUrl('https://ghcr.io/token?service=ghcr.io')).toBe(
      'https://ghcr.io/token?service=ghcr.io',
    );
  });

  it('refuses Docker Hub, ECR, GCR, ACR, and GitHub API hosts', () => {
    expect(() => allowlistedGhcrUrl('https://docker.io/v2/library/nginx/manifests/latest')).toThrow(
      /only ghcr\.io/,
    );
    expect(() =>
      allowlistedGhcrUrl('https://123.dkr.ecr.us-east-1.amazonaws.com/v2/app/manifests/sha256:abc'),
    ).toThrow(/only ghcr\.io/);
    expect(() => allowlistedGhcrUrl('https://gcr.io/v2/proj/app/manifests/latest')).toThrow(/only ghcr\.io/);
    expect(() => allowlistedGhcrUrl('https://myregistry.azurecr.io/v2/app/manifests/latest')).toThrow(
      /only ghcr\.io/,
    );
    expect(() => allowlistedGhcrUrl('https://api.github.com/orgs/acme/packages')).toThrow(/only ghcr\.io/);
  });

  it('refuses suffix-confusion, http, userinfo, and non-default ports', () => {
    expect(() => allowlistedGhcrUrl('https://ghcr.io.evil.example/v2/acme/app/manifests/x')).toThrow(
      /only ghcr\.io/,
    );
    expect(() => allowlistedGhcrUrl('http://ghcr.io/v2/acme/app/manifests/x')).toThrow(/non-https/);
    expect(() => allowlistedGhcrUrl('https://user:pass@ghcr.io/v2/acme/app/manifests/x')).toThrow(/userinfo/);
    expect(() => allowlistedGhcrUrl('https://ghcr.io:8443/v2/acme/app/manifests/x')).toThrow(/port/);
  });
});

describe('isGhcrRegistryHost', () => {
  it('accepts only ghcr.io', () => {
    expect(isGhcrRegistryHost('ghcr.io')).toBe(true);
    expect(isGhcrRegistryHost('GHCR.IO')).toBe(true);
    expect(isGhcrRegistryHost('ghcr.io.')).toBe(true);
    expect(isGhcrRegistryHost('docker.io')).toBe(false);
    expect(isGhcrRegistryHost('pkg-containers.githubusercontent.com')).toBe(false);
  });
});

describe('ghcrManifestUrl / ghcrBlobUrl / ghcrTokenUrl', () => {
  it(`builds registry URLs on ${GHCR_REGISTRY_HOST} only`, () => {
    expect(ghcrManifestUrl('acme', 'payments-api', DIGEST)).toBe(
      `https://ghcr.io/v2/acme/payments-api/manifests/${DIGEST}`,
    );
    expect(ghcrBlobUrl('acme', 'foo/bar', DIGEST)).toBe(`https://ghcr.io/v2/acme/foo/bar/blobs/${DIGEST}`);
    expect(ghcrTokenUrl('acme', 'payments-api')).toContain('https://ghcr.io/token?');
    expect(ghcrTokenUrl('acme', 'payments-api')).toContain(encodeURIComponent('repository:acme/payments-api:pull'));
  });
});

describe('allowlistedGhcrBlobRedirect', () => {
  it('allows the GitHub package CDN and ghcr.io, refuses everything else', () => {
    expect(allowlistedGhcrBlobRedirect('https://pkg-containers.githubusercontent.com/ghcr1/blob')).toBe(
      'https://pkg-containers.githubusercontent.com/ghcr1/blob',
    );
    expect(allowlistedGhcrBlobRedirect(`https://ghcr.io/v2/acme/app/blobs/${DIGEST}`)).toContain('ghcr.io');
    expect(() => allowlistedGhcrBlobRedirect('https://evil.example/blob')).toThrow(/redirect host/);
    expect(() => allowlistedGhcrBlobRedirect('https://docker.io/v2/library/nginx/blobs/sha256:x')).toThrow(
      /redirect host/,
    );
  });
});

describe('refuseTenantWritableRegistry', () => {
  it('allows owner/package/digest identity fields', () => {
    expect(() =>
      refuseTenantWritableRegistry({ owner: 'acme', package: 'app', digest: DIGEST }),
    ).not.toThrow();
  });

  it('refuses tenant-writable registry hosts including registryUrl and ghcrUrl', () => {
    expect(() => refuseTenantWritableRegistry({ owner: 'acme', registryUrl: 'https://ghcr.io' })).toThrow(
      /tenant-writable/,
    );
    expect(() => refuseTenantWritableRegistry({ owner: 'acme', ghcrUrl: 'https://ghcr.io/v2/' })).toThrow(
      /tenant-writable/,
    );
    expect(() => refuseTenantWritableRegistry({ owner: 'acme', endpoint: 'https://docker.io' })).toThrow(
      /tenant-writable/,
    );
    expect(() => refuseTenantWritableRegistry({ owner: 'https://evil.example' })).toThrow(/tenant-writable/);
  });
});

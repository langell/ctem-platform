import { describe, expect, it } from 'vitest';
import {
  DOCKERHUB_HUB_HOST,
  TENANT_ENDPOINT_KEYS,
  allowlistedDockerhubUrl,
  dockerhubLoginUrl,
  dockerhubRepositoriesUrl,
  dockerhubTagsUrl,
  dockerhubTokenUrl,
  isDockerhubHubHost,
  refuseTenantWritableEndpoint,
} from './dockerhub.egress';

describe('allowlistedDockerhubUrl', () => {
  it('accepts hub.docker.com over https/443', () => {
    expect(allowlistedDockerhubUrl('https://hub.docker.com/v2/repositories/acme/')).toBe(
      'https://hub.docker.com/v2/repositories/acme/',
    );
    expect(
      allowlistedDockerhubUrl('https://hub.docker.com/v2/repositories/acme/payments-api/tags/?page_size=100'),
    ).toBe('https://hub.docker.com/v2/repositories/acme/payments-api/tags/?page_size=100');
    expect(allowlistedDockerhubUrl('https://hub.docker.com/v2/users/login/')).toBe(
      'https://hub.docker.com/v2/users/login/',
    );
  });

  it('refuses pull-plane hosts and other non-Hub hosts', () => {
    expect(() =>
      allowlistedDockerhubUrl('https://registry-1.docker.io/v2/acme/app/manifests/latest'),
    ).toThrow(/only hub\.docker\.com/);
    expect(() => allowlistedDockerhubUrl('https://index.docker.io/v1/')).toThrow(
      /only hub\.docker\.com/,
    );
    expect(() => allowlistedDockerhubUrl('https://evil.example/v2/repositories/acme/')).toThrow(
      /only hub\.docker\.com/,
    );
  });

  it('refuses suffix-confusion, lookalike, and docker.com (not the Hub host)', () => {
    expect(() => allowlistedDockerhubUrl('https://hub.docker.com.evil.example/')).toThrow(
      /only hub\.docker\.com/,
    );
    expect(() => allowlistedDockerhubUrl('https://evilhub.docker.com/')).toThrow(
      /only hub\.docker\.com/,
    );
    expect(() => allowlistedDockerhubUrl('https://docker.com/v2/repositories/acme/')).toThrow(
      /only hub\.docker\.com/,
    );
    expect(() => allowlistedDockerhubUrl('https://hub.docker.com.evil.example/v2/repositories/acme')).toThrow(
      /only hub\.docker\.com/,
    );
  });

  it('refuses http, userinfo, and non-default ports', () => {
    expect(() => allowlistedDockerhubUrl('http://hub.docker.com/v2/repositories/acme/')).toThrow(
      /non-https/,
    );
    expect(() => allowlistedDockerhubUrl('https://user:pass@hub.docker.com/v2/users/login/')).toThrow(
      /userinfo/,
    );
    expect(() => allowlistedDockerhubUrl('https://hub.docker.com:8443/v2/repositories/acme/')).toThrow(
      /port/,
    );
  });

  it('refuses OCI pull paths even on hub.docker.com', () => {
    expect(() =>
      allowlistedDockerhubUrl('https://hub.docker.com/v2/acme/app/manifests/latest'),
    ).toThrow(/path/);
    expect(() =>
      allowlistedDockerhubUrl('https://hub.docker.com/v2/repositories/acme/app/blobs/sha256:abc'),
    ).toThrow(/path/);
    expect(() =>
      allowlistedDockerhubUrl('https://hub.docker.com/v2/repositories/acme/app/manifests/latest'),
    ).toThrow(/path/);
  });
});

describe('isDockerhubHubHost', () => {
  it('accepts only hub.docker.com', () => {
    expect(isDockerhubHubHost('hub.docker.com')).toBe(true);
    expect(isDockerhubHubHost('HUB.DOCKER.COM')).toBe(true);
    expect(isDockerhubHubHost('hub.docker.com.')).toBe(true);
    expect(isDockerhubHubHost('registry-1.docker.io')).toBe(false);
    expect(isDockerhubHubHost('index.docker.io')).toBe(false);
    expect(isDockerhubHubHost('docker.com')).toBe(false);
    expect(isDockerhubHubHost('hub.docker.com.evil.example')).toBe(false);
  });
});

describe('dockerhubRepositoriesUrl / dockerhubTagsUrl / login', () => {
  it('builds Hub listing URLs on hub.docker.com, never the pull plane', () => {
    expect(dockerhubLoginUrl()).toBe(`https://${DOCKERHUB_HUB_HOST}/v2/users/login/`);
    expect(dockerhubTokenUrl()).toBe(`https://${DOCKERHUB_HUB_HOST}/v2/auth/token/`);
    expect(dockerhubRepositoriesUrl('acme')).toBe(
      `https://${DOCKERHUB_HUB_HOST}/v2/repositories/acme/?page_size=100`,
    );
    expect(dockerhubTagsUrl('acme', 'payments-api')).toBe(
      `https://${DOCKERHUB_HUB_HOST}/v2/repositories/acme/payments-api/tags/?page_size=100`,
    );
  });

  it('refuses query-shaped or path-shaped ids instead of interpolating them', () => {
    expect(() => dockerhubRepositoriesUrl('acme?evil=1')).toThrow(/namespace/);
    expect(() => dockerhubTagsUrl('acme', 'foo/bar')).toThrow(/repository/);
  });

  it('refuses a namespace that is a host or URL', () => {
    expect(() => dockerhubRepositoriesUrl('https://evil.example')).toThrow(/namespace/);
    expect(() => dockerhubRepositoriesUrl('hub.docker.com')).toThrow(/namespace/);
    expect(() => dockerhubRepositoriesUrl('registry-1.docker.io')).toThrow(/namespace/);
    expect(() => dockerhubRepositoriesUrl('index.docker.io')).toThrow(/namespace/);
    expect(() => dockerhubTagsUrl('acme', 'index.docker.io')).toThrow(/repository/);
  });
});

describe('refuseTenantWritableEndpoint', () => {
  it('allows a namespace-only config', () => {
    expect(() => refuseTenantWritableEndpoint({ namespace: 'acme' })).not.toThrow();
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', repositories: ['payments-api'] }),
    ).not.toThrow();
  });

  it('refuses tenant-writable endpoint keys including registry/index/hub hosts', () => {
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', endpoint: 'https://evil.example' }),
    ).toThrow(/tenant-writable Docker Hub endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', registryUrl: 'https://registry-1.docker.io' }),
    ).toThrow(/tenant-writable Docker Hub endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', hubUrl: 'https://hub.docker.com' }),
    ).toThrow(/tenant-writable Docker Hub endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', indexUrl: 'https://index.docker.io' }),
    ).toThrow(/tenant-writable Docker Hub endpoint/);
    expect(() => refuseTenantWritableEndpoint({ namespace: 'acme', registryHost: 'index.docker.io' })).toThrow(
      /tenant-writable Docker Hub endpoint/,
    );
    expect(() => refuseTenantWritableEndpoint({ namespace: 'acme', authority: 'hub.docker.com' })).toThrow(
      /tenant-writable Docker Hub endpoint/,
    );
    expect(() =>
      refuseTenantWritableEndpoint({
        namespace: 'acme',
        customEndpoint: 'https://hub.docker.com.evil.example',
      }),
    ).toThrow(/tenant-writable Docker Hub endpoint/);
    expect(TENANT_ENDPOINT_KEYS).toContain('registryUrl');
    expect(TENANT_ENDPOINT_KEYS).toContain('hubUrl');
    expect(TENANT_ENDPOINT_KEYS).toContain('indexUrl');
    expect(TENANT_ENDPOINT_KEYS).toContain('authority');
  });

  it('refuses EXTRA_*_HOST_KEYS', () => {
    expect(() =>
      refuseTenantWritableEndpoint({
        namespace: 'acme',
        EXTRA_DOCKERHUB_HOST_KEYS: ['evil.example'],
      }),
    ).toThrow(/tenant-writable Docker Hub endpoint/);
  });

  it('refuses a namespace / repository that is itself a URL or host', () => {
    expect(() => refuseTenantWritableEndpoint({ namespace: 'https://evil.example' })).toThrow(
      /tenant-writable Docker Hub endpoint/,
    );
    expect(() => refuseTenantWritableEndpoint({ namespace: 'hub.docker.com' })).toThrow(
      /tenant-writable Docker Hub endpoint/,
    );
    expect(() => refuseTenantWritableEndpoint({ namespace: 'index.docker.io' })).toThrow(
      /tenant-writable Docker Hub endpoint/,
    );
    expect(() =>
      refuseTenantWritableEndpoint({
        namespace: 'acme',
        repositories: ['https://registry-1.docker.io/acme/app'],
      }),
    ).toThrow(/tenant-writable Docker Hub endpoint/);
  });
});

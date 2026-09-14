import { describe, expect, it } from 'vitest';
import {
  TENANT_ENDPOINT_KEYS,
  allowlistedGcrApiUrl,
  gcrDockerImagesUrl,
  gcrRepositoriesUrl,
  isArtifactRegistryApiHost,
  refuseTenantWritableEndpoint,
} from './gcr.egress';

describe('allowlistedGcrApiUrl', () => {
  it('accepts Artifact Registry API hosts', () => {
    expect(
      allowlistedGcrApiUrl(
        'https://artifactregistry.googleapis.com/v1/projects/acme-prod/locations/us/repositories',
      ),
    ).toBe(
      'https://artifactregistry.googleapis.com/v1/projects/acme-prod/locations/us/repositories',
    );
  });

  it('refuses gcr.io / pkg.dev pull hosts and other non-AR API hosts', () => {
    expect(() => allowlistedGcrApiUrl('https://gcr.io/v2/acme-prod/app/manifests/latest')).toThrow(
      /only googleapis\.com/,
    );
    expect(() =>
      allowlistedGcrApiUrl('https://us-docker.pkg.dev/v2/acme-prod/app/blobs/sha256:abc'),
    ).toThrow(/only googleapis\.com/);
    expect(() => allowlistedGcrApiUrl('https://compute.googleapis.com/')).toThrow(
      /only artifactregistry\.googleapis\.com/,
    );
    expect(() => allowlistedGcrApiUrl('https://evil.example/ar')).toThrow(/only googleapis\.com/);
  });

  it('refuses suffix-confusion and lookalike hosts', () => {
    expect(() =>
      allowlistedGcrApiUrl('https://artifactregistry.googleapis.com.evil.example/'),
    ).toThrow(/only googleapis\.com/);
    expect(() => allowlistedGcrApiUrl('https://artifactregistry.evilgoogleapis.com/')).toThrow(
      /only googleapis\.com/,
    );
  });

  it('refuses http, userinfo, and non-default ports', () => {
    expect(() => allowlistedGcrApiUrl('http://artifactregistry.googleapis.com/')).toThrow(
      /non-https/,
    );
    expect(() =>
      allowlistedGcrApiUrl('https://user:pass@artifactregistry.googleapis.com/'),
    ).toThrow(/userinfo/);
    expect(() => allowlistedGcrApiUrl('https://artifactregistry.googleapis.com:8443/')).toThrow(
      /port/,
    );
  });
});

describe('isArtifactRegistryApiHost', () => {
  it('accepts artifactregistry.googleapis.com only', () => {
    expect(isArtifactRegistryApiHost('artifactregistry.googleapis.com')).toBe(true);
    expect(isArtifactRegistryApiHost('ARTIFACTREGISTRY.GOOGLEAPIS.COM')).toBe(true);
    expect(isArtifactRegistryApiHost('gcr.io')).toBe(false);
    expect(isArtifactRegistryApiHost('us-docker.pkg.dev')).toBe(false);
    expect(isArtifactRegistryApiHost('oauth2.googleapis.com')).toBe(false);
    expect(isArtifactRegistryApiHost('artifactregistry.googleapis.com.evil.example')).toBe(false);
  });
});

describe('gcrRepositoriesUrl / gcrDockerImagesUrl', () => {
  it('builds AR list URLs from project/location/repo ids, never a tenant host', () => {
    expect(gcrRepositoriesUrl('acme-prod', 'us-central1')).toBe(
      'https://artifactregistry.googleapis.com/v1/projects/acme-prod/locations/us-central1/repositories',
    );
    expect(gcrRepositoriesUrl('acme-prod', '-')).toBe(
      'https://artifactregistry.googleapis.com/v1/projects/acme-prod/locations/-/repositories',
    );
    expect(gcrDockerImagesUrl('acme-prod', 'us', 'gcr.io')).toBe(
      'https://artifactregistry.googleapis.com/v1/projects/acme-prod/locations/us/repositories/gcr.io/dockerImages',
    );
    expect(gcrDockerImagesUrl('acme-prod', 'us-central1', 'payments-api')).toBe(
      'https://artifactregistry.googleapis.com/v1/projects/acme-prod/locations/us-central1/repositories/payments-api/dockerImages',
    );
  });

  it('encodes ids in the path so they cannot become a host', () => {
    expect(gcrDockerImagesUrl('acme-prod', 'us', 'gcr.io')).toContain('/repositories/gcr.io/');
    expect(gcrRepositoriesUrl('acme-prod', 'us')).toContain('/projects/acme-prod/locations/us/');
  });

  it('refuses a projectId or location that is not an identifier', () => {
    expect(() => gcrRepositoriesUrl('acme-prod.evil.example', 'us')).toThrow(/projectId/);
    expect(() => gcrRepositoriesUrl('https://evil.example', 'us')).toThrow(/projectId/);
    expect(() => gcrDockerImagesUrl('acme-prod', 'us-docker.pkg.dev', 'app')).toThrow(/location/);
    expect(() => gcrDockerImagesUrl('acme-prod', 'https://gcr.io', 'app')).toThrow(/location/);
    expect(() => gcrDockerImagesUrl('acme-prod', 'us', 'https://gcr.io/app')).toThrow(/repository/);
  });
});

describe('refuseTenantWritableEndpoint', () => {
  it('allows a projectId-only config', () => {
    expect(() => refuseTenantWritableEndpoint({ projectId: 'acme-prod' })).not.toThrow();
    expect(() =>
      refuseTenantWritableEndpoint({ projectId: 'acme-prod', locations: ['us-central1'] }),
    ).not.toThrow();
  });

  it('refuses tenant-writable endpoint keys including registry/gcr hosts', () => {
    expect(() =>
      refuseTenantWritableEndpoint({ projectId: 'acme-prod', endpoint: 'https://evil.example' }),
    ).toThrow(/tenant-writable GCR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        projectId: 'acme-prod',
        registryUrl: 'https://gcr.io',
      }),
    ).toThrow(/tenant-writable GCR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        projectId: 'acme-prod',
        gcrUrl: 'https://us-docker.pkg.dev/acme-prod/app',
      }),
    ).toThrow(/tenant-writable GCR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        projectId: 'acme-prod',
        artifactRegistryUrl: 'https://artifactregistry.googleapis.com',
      }),
    ).toThrow(/tenant-writable GCR endpoint/);
    expect(() => refuseTenantWritableEndpoint({ projectId: 'acme-prod', host: 'gcr.io' })).toThrow(
      /tenant-writable GCR endpoint/,
    );
    expect(() =>
      refuseTenantWritableEndpoint({
        projectId: 'acme-prod',
        customEndpoint: 'https://artifactregistry.googleapis.com.evil.example',
      }),
    ).toThrow(/tenant-writable GCR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        projectId: 'acme-prod',
        tokenUri: 'https://evil.example/token',
      }),
    ).toThrow(/tenant-writable GCR endpoint/);
    expect(TENANT_ENDPOINT_KEYS).toContain('registryUrl');
    expect(TENANT_ENDPOINT_KEYS).toContain('gcrUrl');
  });

  it('refuses EXTRA_*_HOST_KEYS', () => {
    expect(() =>
      refuseTenantWritableEndpoint({
        projectId: 'acme-prod',
        EXTRA_GCR_HOST_KEYS: ['evil.example'],
      }),
    ).toThrow(/tenant-writable GCR endpoint/);
  });

  it('refuses a projectId / location / repository that is itself a URL', () => {
    expect(() => refuseTenantWritableEndpoint({ projectId: 'https://evil.example' })).toThrow(
      /tenant-writable GCR endpoint/,
    );
    expect(() =>
      refuseTenantWritableEndpoint({ projectId: 'acme-prod', location: 'https://gcr.io' }),
    ).toThrow(/tenant-writable GCR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        projectId: 'acme-prod',
        repositories: ['https://us-docker.pkg.dev/acme/app'],
      }),
    ).toThrow(/tenant-writable GCR endpoint/);
  });
});

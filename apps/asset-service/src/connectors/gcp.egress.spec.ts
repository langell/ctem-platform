import { describe, expect, it } from 'vitest';
import {
  allowlistedGcpUrl,
  gcpComputeUrl,
  gcpStorageBucketsUrl,
  isGcpApiHost,
  refuseTenantWritableEndpoint,
} from './gcp.egress';

describe('allowlistedGcpUrl', () => {
  it('accepts Google API hosts', () => {
    expect(allowlistedGcpUrl('https://oauth2.googleapis.com/token')).toBe(
      'https://oauth2.googleapis.com/token',
    );
    expect(allowlistedGcpUrl('https://compute.googleapis.com/compute/v1/projects/acme/aggregated/instances')).toBe(
      'https://compute.googleapis.com/compute/v1/projects/acme/aggregated/instances',
    );
    expect(allowlistedGcpUrl('https://storage.googleapis.com/storage/v1/b?project=acme')).toBe(
      'https://storage.googleapis.com/storage/v1/b?project=acme',
    );
  });

  it('refuses a tenant-writable host', () => {
    expect(() => allowlistedGcpUrl('https://evil.example/gcp')).toThrow(/only googleapis\.com/);
  });

  it('refuses suffix-confusion and lookalike hosts', () => {
    expect(() =>
      allowlistedGcpUrl('https://compute.googleapis.com.evil.example/'),
    ).toThrow(/only googleapis\.com/);
    expect(() => allowlistedGcpUrl('https://evilgoogleapis.com/')).toThrow(/only googleapis\.com/);
    expect(() => allowlistedGcpUrl('https://googleapis.com.evil.example/')).toThrow(
      /only googleapis\.com/,
    );
    expect(() => allowlistedGcpUrl('https://storage.cloud.google.com/')).toThrow(
      /only googleapis\.com/,
    );
  });

  it('refuses http, userinfo, and non-default ports', () => {
    expect(() => allowlistedGcpUrl('http://compute.googleapis.com/')).toThrow(/non-https/);
    expect(() => allowlistedGcpUrl('https://user:pass@compute.googleapis.com/')).toThrow(/userinfo/);
    expect(() => allowlistedGcpUrl('https://compute.googleapis.com:8443/')).toThrow(/port/);
  });
});

describe('isGcpApiHost', () => {
  it('accepts googleapis.com and its subdomains only', () => {
    expect(isGcpApiHost('oauth2.googleapis.com')).toBe(true);
    expect(isGcpApiHost('compute.googleapis.com')).toBe(true);
    expect(isGcpApiHost('storage.googleapis.com')).toBe(true);
    expect(isGcpApiHost('googleapis.com')).toBe(true);
    expect(isGcpApiHost('evil.example')).toBe(false);
    expect(isGcpApiHost('googleapis.com.evil.example')).toBe(false);
    expect(isGcpApiHost('storage.cloud.google.com')).toBe(false);
  });
});

describe('gcpComputeUrl / gcpStorageBucketsUrl', () => {
  it('derives Compute and Storage hosts from a project id, never a tenant host', () => {
    expect(gcpComputeUrl('acme-prod', '/aggregated/instances')).toBe(
      'https://compute.googleapis.com/compute/v1/projects/acme-prod/aggregated/instances',
    );
    expect(gcpComputeUrl('acme-prod', '/global/firewalls')).toBe(
      'https://compute.googleapis.com/compute/v1/projects/acme-prod/global/firewalls',
    );
    expect(gcpStorageBucketsUrl('acme-prod')).toBe(
      'https://storage.googleapis.com/storage/v1/b?project=acme-prod',
    );
  });

  it('refuses a projectId that is not a GCP project identifier', () => {
    expect(() => gcpComputeUrl('acme-prod.evil.example', '/aggregated/instances')).toThrow(
      /projectId/,
    );
    expect(() => gcpComputeUrl('https://evil.example', '/aggregated/instances')).toThrow(
      /projectId/,
    );
  });
});

describe('refuseTenantWritableEndpoint', () => {
  it('allows a projectId-only config', () => {
    expect(() => refuseTenantWritableEndpoint({ projectId: 'acme-prod' })).not.toThrow();
  });

  it('refuses tenant-writable endpoint keys', () => {
    expect(() =>
      refuseTenantWritableEndpoint({ projectId: 'acme-prod', endpoint: 'https://evil.example' }),
    ).toThrow(/tenant-writable GCP endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ projectId: 'acme-prod', apiUrl: 'https://evil.example/gcp' }),
    ).toThrow(/tenant-writable GCP endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ projectId: 'acme-prod', host: 'evil.example' }),
    ).toThrow(/tenant-writable GCP endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        projectId: 'acme-prod',
        tokenUri: 'https://evil.example/token',
      }),
    ).toThrow(/tenant-writable GCP endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        projectId: 'acme-prod',
        universeDomain: 'evil.example',
      }),
    ).toThrow(/tenant-writable GCP endpoint/);
  });

  it('refuses a projectId that is itself a URL', () => {
    expect(() => refuseTenantWritableEndpoint({ projectId: 'https://evil.example' })).toThrow(
      /tenant-writable GCP endpoint/,
    );
  });
});

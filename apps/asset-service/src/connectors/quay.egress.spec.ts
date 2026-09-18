import { describe, expect, it } from 'vitest';
import {
  TENANT_ENDPOINT_KEYS,
  allowlistedQuayApiUrl,
  isQuayApiHost,
  quayRepositoriesUrl,
  quayTagsUrl,
  refuseTenantWritableEndpoint,
} from './quay.egress';

describe('allowlistedQuayApiUrl', () => {
  it('accepts quay.io over https/443 under /api/v1', () => {
    expect(allowlistedQuayApiUrl('https://quay.io/api/v1/repository?namespace=acme')).toBe(
      'https://quay.io/api/v1/repository?namespace=acme',
    );
    expect(allowlistedQuayApiUrl('https://quay.io/api/v1/repository/acme/app/tag?limit=100')).toBe(
      'https://quay.io/api/v1/repository/acme/app/tag?limit=100',
    );
  });

  it('refuses OCI pull paths and other non-API hosts', () => {
    expect(() => allowlistedQuayApiUrl('https://quay.io/v2/acme/app/manifests/latest')).toThrow(
      /\/api\/v1/,
    );
    expect(() => allowlistedQuayApiUrl('https://quay.io/v2/acme/app/blobs/sha256:abc')).toThrow(
      /\/api\/v1/,
    );
    expect(() => allowlistedQuayApiUrl('https://cdn.quay.io/api/v1/repository')).toThrow(
      /only quay\.io/,
    );
    expect(() => allowlistedQuayApiUrl('https://evil.example/quay')).toThrow(/only quay\.io/);
  });

  it('refuses suffix-confusion, lookalike, and self-hosted Quay hosts', () => {
    expect(() => allowlistedQuayApiUrl('https://quay.io.evil.example/api/v1/repository')).toThrow(
      /only quay\.io/,
    );
    expect(() => allowlistedQuayApiUrl('https://notquay.io/api/v1/repository')).toThrow(
      /only quay\.io/,
    );
    expect(() => allowlistedQuayApiUrl('https://quay.example.com/api/v1/repository')).toThrow(
      /only quay\.io/,
    );
    expect(() => allowlistedQuayApiUrl('https://registry.internal/api/v1/repository')).toThrow(
      /only quay\.io/,
    );
    expect(() => allowlistedQuayApiUrl('https://www.quay.io/api/v1/repository')).toThrow(
      /only quay\.io/,
    );
  });

  it('refuses http, userinfo, and non-default ports', () => {
    expect(() => allowlistedQuayApiUrl('http://quay.io/api/v1/repository')).toThrow(/non-https/);
    expect(() => allowlistedQuayApiUrl('https://user:pass@quay.io/api/v1/repository')).toThrow(
      /userinfo/,
    );
    expect(() => allowlistedQuayApiUrl('https://quay.io:8443/api/v1/repository')).toThrow(/port/);
  });
});

describe('isQuayApiHost', () => {
  it('accepts only exact quay.io', () => {
    expect(isQuayApiHost('quay.io')).toBe(true);
    expect(isQuayApiHost('QUAY.IO')).toBe(true);
    expect(isQuayApiHost('quay.io.')).toBe(true);
    expect(isQuayApiHost('cdn.quay.io')).toBe(false);
    expect(isQuayApiHost('www.quay.io')).toBe(false);
    expect(isQuayApiHost('quay.io.evil.example')).toBe(false);
    expect(isQuayApiHost('notquay.io')).toBe(false);
  });
});

describe('quayRepositoriesUrl / quayTagsUrl', () => {
  it('builds /api/v1 URLs on quay.io from namespace/repository ids, never a tenant host', () => {
    expect(quayRepositoriesUrl('acme')).toBe(
      'https://quay.io/api/v1/repository?namespace=acme&repo_kind=image',
    );
    expect(quayTagsUrl('acme', 'payments-api', 1)).toBe(
      'https://quay.io/api/v1/repository/acme/payments-api/tag?limit=100&page=1&onlyActiveTags=true',
    );
  });

  it('encodes ids in the path so they cannot become a host', () => {
    expect(quayTagsUrl('acme', 'foo/bar', 2)).toContain('/repository/acme/foo/bar/tag');
    expect(quayTagsUrl('acme', 'foo/bar', 2)).toContain('page=2');
    expect(quayRepositoriesUrl('acme_org')).toContain('namespace=acme_org');
  });

  it('allowlists a leftover next_page URL and refuses an off-host one', () => {
    expect(
      quayRepositoriesUrl('acme', 'https://quay.io/api/v1/repository?namespace=acme&next_page=tok'),
    ).toBe('https://quay.io/api/v1/repository?namespace=acme&next_page=tok');
    expect(() =>
      quayRepositoriesUrl('acme', 'https://evil.example/api/v1/repository?next_page=tok'),
    ).toThrow(/only quay\.io/);
    expect(() =>
      quayRepositoriesUrl('acme', 'https://quay.io.evil.example/api/v1/repository'),
    ).toThrow(/only quay\.io/);
  });

  it('refuses a namespace or repository that is not an identifier', () => {
    expect(() => quayRepositoriesUrl('https://evil.example')).toThrow(/namespace/);
    expect(() => quayRepositoriesUrl('acme/../evil')).toThrow(/namespace/);
    expect(() => quayTagsUrl('acme', 'https://quay.io/acme/app', 1)).toThrow(/repository/);
    expect(() => quayTagsUrl('https://quay.io', 'app', 1)).toThrow(/namespace/);
  });
});

describe('refuseTenantWritableEndpoint', () => {
  it('allows a namespace-only config', () => {
    expect(() => refuseTenantWritableEndpoint({ namespace: 'acme' })).not.toThrow();
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', repositories: ['payments-api'] }),
    ).not.toThrow();
  });

  it('refuses tenant-writable endpoint keys including registry/quay hosts', () => {
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', endpoint: 'https://evil.example' }),
    ).toThrow(/tenant-writable Quay endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', apiUrl: 'https://evil.example/quay' }),
    ).toThrow(/tenant-writable Quay endpoint/);
    expect(() => refuseTenantWritableEndpoint({ namespace: 'acme', host: 'quay.io' })).toThrow(
      /tenant-writable Quay endpoint/,
    );
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', baseUrl: 'https://quay.internal' }),
    ).toThrow(/tenant-writable Quay endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', quayUrl: 'https://quay.io' }),
    ).toThrow(/tenant-writable Quay endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', authority: 'https://quay.io' }),
    ).toThrow(/tenant-writable Quay endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        namespace: 'acme',
        registryUrl: 'https://quay.io.evil.example',
      }),
    ).toThrow(/tenant-writable Quay endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ namespace: 'acme', url: 'https://quay.io.evil.example' }),
    ).toThrow(/tenant-writable Quay endpoint/);
    expect(TENANT_ENDPOINT_KEYS).toContain('registryUrl');
    expect(TENANT_ENDPOINT_KEYS).toContain('quayUrl');
    expect(TENANT_ENDPOINT_KEYS).toContain('authority');
    expect(TENANT_ENDPOINT_KEYS).toContain('baseUrl');
    expect(TENANT_ENDPOINT_KEYS).toContain('host');
  });

  it('refuses EXTRA_*_HOST_KEYS', () => {
    expect(() =>
      refuseTenantWritableEndpoint({
        namespace: 'acme',
        EXTRA_QUAY_HOST_KEYS: ['evil.example'],
      }),
    ).toThrow(/tenant-writable Quay endpoint/);
  });

  it('refuses a namespace / repository that is itself a URL', () => {
    expect(() => refuseTenantWritableEndpoint({ namespace: 'https://evil.example' })).toThrow(
      /tenant-writable Quay endpoint/,
    );
    expect(() =>
      refuseTenantWritableEndpoint({
        namespace: 'acme',
        repositories: ['https://quay.io/acme/app'],
      }),
    ).toThrow(/tenant-writable Quay endpoint/);
  });
});

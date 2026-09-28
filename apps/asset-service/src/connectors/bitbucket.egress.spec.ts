import { describe, expect, it } from 'vitest';
import {
  BITBUCKET_API_HOST,
  BITBUCKET_API_ORIGIN,
  EXTRA_HOST_KEY_RE,
  TENANT_ENDPOINT_KEYS,
  allowlistedBitbucketApiUrl,
  bitbucketCloneUrl,
  bitbucketHtmlUrl,
  bitbucketRepositoriesUrl,
  refuseTenantWritableEndpoint,
} from './bitbucket.egress';

describe('allowlistedBitbucketApiUrl', () => {
  it('allows the pinned Cloud API host and workspace path', () => {
    const raw = `${BITBUCKET_API_ORIGIN}/2.0/repositories/langell?pagelen=100&page=1`;
    expect(allowlistedBitbucketApiUrl(raw, 'langell')).toBe(
      `https://${BITBUCKET_API_HOST}/2.0/repositories/langell?pagelen=100&page=1`,
    );
    expect(allowlistedBitbucketApiUrl(`https://API.BITBUCKET.ORG./2.0/repositories/langell`, 'langell')).toBe(
      `https://${BITBUCKET_API_HOST}/2.0/repositories/langell`,
    );
  });

  it('refuses lookalike hosts, the html host, and non-https', () => {
    expect(() =>
      allowlistedBitbucketApiUrl('https://api.bitbucket.org.evil.example/2.0/repositories/langell', 'langell'),
    ).toThrow(/only api\.bitbucket\.org is allowlisted/);
    expect(() =>
      allowlistedBitbucketApiUrl('https://evil.api.bitbucket.org/2.0/repositories/langell', 'langell'),
    ).toThrow(/only api\.bitbucket\.org is allowlisted/);
    expect(() =>
      allowlistedBitbucketApiUrl('https://bitbucket.org/2.0/repositories/langell', 'langell'),
    ).toThrow(/only api\.bitbucket\.org is allowlisted/);
    expect(() =>
      allowlistedBitbucketApiUrl('https://api-bitbucket.org/2.0/repositories/langell', 'langell'),
    ).toThrow(/only api\.bitbucket\.org is allowlisted/);
    expect(() =>
      allowlistedBitbucketApiUrl('http://api.bitbucket.org/2.0/repositories/langell', 'langell'),
    ).toThrow(/non-https/);
  });

  it('refuses userinfo, a non-default port, and Server/Data Center paths', () => {
    expect(() =>
      allowlistedBitbucketApiUrl('https://user:token@api.bitbucket.org/2.0/repositories/langell', 'langell'),
    ).toThrow(/userinfo/);
    expect(() =>
      allowlistedBitbucketApiUrl('https://api.bitbucket.org:8443/2.0/repositories/langell', 'langell'),
    ).toThrow(/non-default port/);
    expect(() =>
      allowlistedBitbucketApiUrl('https://api.bitbucket.org/rest/api/1.0/projects/ACME/repos', 'langell'),
    ).toThrow(/only \/2\.0\/repositories\/langell/);
    expect(() =>
      allowlistedBitbucketApiUrl('https://api.bitbucket.org/2.0/repositories/other', 'langell'),
    ).toThrow(/only \/2\.0\/repositories\/langell/);
    expect(() =>
      allowlistedBitbucketApiUrl('https://api.bitbucket.org/2.0/repositories/langell/src', 'langell'),
    ).toThrow(/only \/2\.0\/repositories\/langell/);
  });
});

describe('bitbucketRepositoriesUrl', () => {
  it('builds the first page on the pinned host', () => {
    expect(bitbucketRepositoriesUrl('langell', 1, 100)).toBe(
      'https://api.bitbucket.org/2.0/repositories/langell?pagelen=100&page=1',
    );
  });

  it('refuses a workspace that is a host or a URL', () => {
    expect(() => bitbucketRepositoriesUrl('bitbucket.org', 1, 100)).toThrow(/not hosts/);
    expect(() => bitbucketRepositoriesUrl('api.bitbucket.org', 1, 100)).toThrow(/not hosts/);
    expect(() => bitbucketRepositoriesUrl('https://evil.example', 1, 100)).toThrow(/not a valid/);
    expect(() => bitbucketRepositoriesUrl('acme/../other', 1, 100)).toThrow(/not a valid/);
  });
});

describe('synthesized bitbucket.org URLs', () => {
  it('builds clone and html URLs from workspace and slug only', () => {
    expect(bitbucketHtmlUrl('langell', 'ctem-scan-target')).toBe(
      'https://bitbucket.org/langell/ctem-scan-target',
    );
    expect(bitbucketCloneUrl('langell', 'ctem-scan-target')).toBe(
      'https://bitbucket.org/langell/ctem-scan-target.git',
    );
  });
});

describe('refuseTenantWritableEndpoint', () => {
  it('allows workspace config and an optional slug allowlist', () => {
    expect(() => refuseTenantWritableEndpoint({ workspace: 'langell' })).not.toThrow();
    expect(() =>
      refuseTenantWritableEndpoint({
        workspace: 'langell',
        repos: ['ctem-scan-target'],
        includeArchived: false,
        includeForks: false,
      }),
    ).not.toThrow();
  });

  it('refuses tenant host, apiUrl, bitbucketUrl, baseUrl, and authority', () => {
    for (const key of ['host', 'apiUrl', 'bitbucketUrl', 'baseUrl', 'authority'] as const) {
      expect(TENANT_ENDPOINT_KEYS).toContain(key);
      expect(() => refuseTenantWritableEndpoint({ workspace: 'langell', [key]: 'https://evil.example' })).toThrow(
        new RegExp(`tenant-writable Bitbucket endpoint \\(${key}\\)`),
      );
    }
    expect(() =>
      refuseTenantWritableEndpoint({ workspace: 'langell', bitbucketServerUrl: 'https://bitbucket.internal' }),
    ).toThrow(/bitbucketServerUrl/);
    expect(() =>
      refuseTenantWritableEndpoint({ workspace: 'langell', dataCenterUrl: 'https://bitbucket.internal' }),
    ).toThrow(/dataCenterUrl/);
  });

  it('refuses EXTRA_*_HOST_KEYS', () => {
    expect(EXTRA_HOST_KEY_RE.test('EXTRA_BITBUCKET_HOST_KEYS')).toBe(true);
    expect(() =>
      refuseTenantWritableEndpoint({
        workspace: 'langell',
        EXTRA_BITBUCKET_HOST_KEYS: ['evil.example'],
      }),
    ).toThrow(/EXTRA_\*_HOST_KEYS/);
  });

  it('refuses a workspace or repo slug that is a URL', () => {
    expect(() => refuseTenantWritableEndpoint({ workspace: 'https://evil.example' })).toThrow(/workspace/);
    expect(() =>
      refuseTenantWritableEndpoint({ workspace: 'langell', repos: ['https://evil.example/repo'] }),
    ).toThrow(/repos/);
  });
});

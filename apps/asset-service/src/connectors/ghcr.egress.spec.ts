import { describe, expect, it } from 'vitest';
import {
  GITHUB_API_HOST,
  allowlistedGithubApiUrl,
  ghcrPackageVersionsUrl,
  ghcrPackagesUrl,
  isGithubApiHost,
  nextRelFromLinkHeader,
  refuseTenantWritableEndpoint,
} from './ghcr.egress';

describe('allowlistedGithubApiUrl', () => {
  it('accepts api.github.com over https/443', () => {
    expect(allowlistedGithubApiUrl('https://api.github.com/orgs/acme/packages')).toBe(
      'https://api.github.com/orgs/acme/packages',
    );
    expect(
      allowlistedGithubApiUrl('https://api.github.com/users/octocat/packages?package_type=container'),
    ).toBe('https://api.github.com/users/octocat/packages?package_type=container');
  });

  it('refuses ghcr.io and other non-GitHub API hosts', () => {
    expect(() => allowlistedGithubApiUrl('https://ghcr.io/v2/acme/app/manifests/latest')).toThrow(
      /only api\.github\.com/,
    );
    expect(() => allowlistedGithubApiUrl('https://evil.example/github')).toThrow(/only api\.github\.com/);
  });

  it('refuses suffix-confusion, lookalike, and github.com (not the API host)', () => {
    expect(() => allowlistedGithubApiUrl('https://api.github.com.evil.example/')).toThrow(
      /only api\.github\.com/,
    );
    expect(() => allowlistedGithubApiUrl('https://evilapi.github.com/')).toThrow(/only api\.github\.com/);
    expect(() => allowlistedGithubApiUrl('https://github.com/orgs/acme/packages')).toThrow(
      /only api\.github\.com/,
    );
    expect(() => allowlistedGithubApiUrl('https://api.github.com.evil.example/orgs/acme')).toThrow(
      /only api\.github\.com/,
    );
  });

  it('refuses http, userinfo, and non-default ports', () => {
    expect(() => allowlistedGithubApiUrl('http://api.github.com/orgs/acme/packages')).toThrow(/non-https/);
    expect(() => allowlistedGithubApiUrl('https://user:pass@api.github.com/')).toThrow(/userinfo/);
    expect(() => allowlistedGithubApiUrl('https://api.github.com:8443/')).toThrow(/port/);
  });
});

describe('isGithubApiHost', () => {
  it('accepts only api.github.com', () => {
    expect(isGithubApiHost('api.github.com')).toBe(true);
    expect(isGithubApiHost('API.GITHUB.COM')).toBe(true);
    expect(isGithubApiHost('api.github.com.')).toBe(true);
    expect(isGithubApiHost('ghcr.io')).toBe(false);
    expect(isGithubApiHost('github.com')).toBe(false);
    expect(isGithubApiHost('api.github.com.evil.example')).toBe(false);
  });
});

describe('ghcrPackagesUrl / ghcrPackageVersionsUrl', () => {
  it('builds Packages REST URLs on api.github.com, never ghcr.io', () => {
    expect(ghcrPackagesUrl('acme', 'org')).toBe(
      `https://${GITHUB_API_HOST}/orgs/acme/packages?package_type=container&per_page=100`,
    );
    expect(ghcrPackagesUrl('octocat', 'user')).toBe(
      `https://${GITHUB_API_HOST}/users/octocat/packages?package_type=container&per_page=100`,
    );
    expect(ghcrPackageVersionsUrl('acme', 'org', 'payments-api')).toBe(
      `https://${GITHUB_API_HOST}/orgs/acme/packages/container/payments-api/versions?per_page=100&state=active`,
    );
  });

  it('encodes owner and package name in the path', () => {
    expect(ghcrPackagesUrl('acme?evil=1', 'org')).toContain('/orgs/acme%3Fevil%3D1/packages');
    expect(ghcrPackageVersionsUrl('acme', 'org', 'foo/bar')).toContain(
      '/packages/container/foo%2Fbar/versions',
    );
  });
});

describe('nextRelFromLinkHeader', () => {
  it('reads rel=next and ignores last/prev', () => {
    const next = 'https://api.github.com/orgs/acme/packages?package_type=container&page=2';
    expect(
      nextRelFromLinkHeader(
        `<${next}>; rel="next", <https://api.github.com/orgs/acme/packages?page=5>; rel="last"`,
      ),
    ).toBe(next);
    expect(nextRelFromLinkHeader('<https://api.github.com/x>; rel="last"')).toBeUndefined();
    expect(nextRelFromLinkHeader(null)).toBeUndefined();
  });
});

describe('refuseTenantWritableEndpoint', () => {
  it('allows an owner-only config', () => {
    expect(() => refuseTenantWritableEndpoint({ owner: 'acme', ownerType: 'org' })).not.toThrow();
  });

  it('refuses tenant-writable endpoint keys including registry/ghcr hosts', () => {
    expect(() =>
      refuseTenantWritableEndpoint({ owner: 'acme', endpoint: 'https://evil.example' }),
    ).toThrow(/tenant-writable GHCR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ owner: 'acme', apiUrl: 'https://evil.example/github' }),
    ).toThrow(/tenant-writable GHCR endpoint/);
    expect(() => refuseTenantWritableEndpoint({ owner: 'acme', host: 'evil.example' })).toThrow(
      /tenant-writable GHCR endpoint/,
    );
    expect(() =>
      refuseTenantWritableEndpoint({ owner: 'acme', baseUrl: 'https://ghcr.io' }),
    ).toThrow(/tenant-writable GHCR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ owner: 'acme', registryUrl: 'https://ghcr.io' }),
    ).toThrow(/tenant-writable GHCR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ owner: 'acme', ghcrUrl: 'https://ghcr.io/v2/' }),
    ).toThrow(/tenant-writable GHCR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ owner: 'acme', url: 'https://api.github.com.evil.example' }),
    ).toThrow(/tenant-writable GHCR endpoint/);
  });

  it('refuses an owner that is itself a URL', () => {
    expect(() => refuseTenantWritableEndpoint({ owner: 'https://evil.example' })).toThrow(
      /tenant-writable GHCR endpoint/,
    );
  });
});

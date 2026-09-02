import { describe, expect, it } from 'vitest';
import {
  EXTRA_GITLAB_HOST_KEYS,
  GITLAB_COM,
  GITLAB_COM_API_URL,
  allowlistedGitLabApiUrl,
  parseGitLabBaseUrl,
  refuseExtraGitLabHosts,
} from './gitlab.egress';

describe('parseGitLabBaseUrl', () => {
  it('defaults to gitlab.com when baseUrl is omitted', () => {
    expect(parseGitLabBaseUrl(undefined)).toEqual(GITLAB_COM);
    expect(parseGitLabBaseUrl(null)).toEqual(GITLAB_COM);
    expect(parseGitLabBaseUrl('')).toEqual(GITLAB_COM);
    expect(parseGitLabBaseUrl('https://gitlab.com')).toEqual(GITLAB_COM);
    expect(parseGitLabBaseUrl('https://www.gitlab.com/api/v4')).toEqual(GITLAB_COM);
  });

  it('accepts an https self-hosted origin and strips path/query', () => {
    expect(parseGitLabBaseUrl('https://gitlab.example.com')).toEqual({
      host: 'gitlab.example.com',
      origin: 'https://gitlab.example.com',
      apiUrl: 'https://gitlab.example.com/api/v4',
    });
    expect(parseGitLabBaseUrl('https://gitlab.example.com/api/v4?foo=1')).toEqual({
      host: 'gitlab.example.com',
      origin: 'https://gitlab.example.com',
      apiUrl: 'https://gitlab.example.com/api/v4',
    });
  });

  it('is https-only', () => {
    expect(() => parseGitLabBaseUrl('http://gitlab.example.com')).toThrow(/non-https/);
    expect(() => parseGitLabBaseUrl('ftp://gitlab.example.com')).toThrow(/non-https/);
  });

  it('rejects userinfo and git@', () => {
    expect(() => parseGitLabBaseUrl('https://user:pass@gitlab.example.com')).toThrow(/userinfo/);
    expect(() => parseGitLabBaseUrl('https://glpat-secret@gitlab.example.com')).toThrow(/userinfo/);
    expect(() => parseGitLabBaseUrl('git@gitlab.example.com:acme/api.git')).toThrow(/git@/);
    expect(() => parseGitLabBaseUrl('ssh://git@gitlab.example.com/acme/api.git')).toThrow(/git@/);
  });
});

describe('allowlistedGitLabApiUrl', () => {
  const selfHosted = parseGitLabBaseUrl('https://gitlab.example.com');

  it('allows API URLs on the configured host and refuses any other', () => {
    expect(
      allowlistedGitLabApiUrl('https://gitlab.example.com/api/v4/projects?owned=true', selfHosted),
    ).toContain('https://gitlab.example.com/api/v4/');
    expect(() =>
      allowlistedGitLabApiUrl('https://evil.example/api/v4/projects', selfHosted),
    ).toThrow(/only gitlab\.example\.com is allowlisted/);
    expect(() =>
      allowlistedGitLabApiUrl('https://gitlab.com/api/v4/projects', selfHosted),
    ).toThrow(/only gitlab\.example\.com is allowlisted/);
  });

  it('allows gitlab.com API URLs only against the gitlab.com origin', () => {
    expect(allowlistedGitLabApiUrl(`${GITLAB_COM_API_URL}/projects`, GITLAB_COM)).toContain(
      'https://gitlab.com/api/v4/',
    );
    expect(() =>
      allowlistedGitLabApiUrl('https://gitlab.example.com/api/v4/projects', GITLAB_COM),
    ).toThrow(/only gitlab\.com is allowlisted/);
  });
});

describe('refuseExtraGitLabHosts', () => {
  it('allows owner config and optional baseUrl', () => {
    expect(() =>
      refuseExtraGitLabHosts({ owner: 'acme', ownerType: 'group', baseUrl: 'https://gitlab.example.com' }),
    ).not.toThrow();
  });

  it('refuses extra tenant-writable host fields', () => {
    for (const key of EXTRA_GITLAB_HOST_KEYS) {
      expect(() => refuseExtraGitLabHosts({ owner: 'acme', [key]: 'evil.example' })).toThrow(
        /tenant-writable GitLab host/,
      );
    }
    expect(() =>
      refuseExtraGitLabHosts({
        owner: 'acme',
        baseUrl: 'https://gitlab.example.com',
        host: 'evil.example',
      }),
    ).toThrow(/tenant-writable GitLab host \(host\)/);
  });
});

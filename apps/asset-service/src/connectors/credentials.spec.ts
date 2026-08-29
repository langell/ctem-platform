import { afterEach, describe, expect, it } from 'vitest';
import { resolveCredential } from './credentials';

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
  delete process.env.GITHUB_TEST_TOKEN;
  delete process.env.GITLAB_TOKEN;
});

describe('resolveCredential', () => {
  it('returns undefined when the ref is null', () => {
    expect(resolveCredential(null)).toBeUndefined();
  });

  it('reads an allowlisted GITHUB_* env var', () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    expect(resolveCredential('env:GITHUB_TOKEN')).toBe('ghp_test');
  });

  it('reads an allowlisted GITLAB_* env var', () => {
    process.env.GITLAB_TOKEN = 'glpat_test';
    expect(resolveCredential('env:GITLAB_TOKEN')).toBe('glpat_test');
  });

  it('returns undefined when an allowlisted name is unset (public-listing path)', () => {
    expect(resolveCredential('env:GITHUB_TOKEN')).toBeUndefined();
  });

  it('refuses env:DATABASE_URL instead of reading it', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => resolveCredential('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });

  it('refuses env:PATH instead of reading it', () => {
    expect(() => resolveCredential('env:PATH')).toThrow(/not allowlisted/);
  });

  it('refuses other replica secrets', () => {
    expect(() => resolveCredential('env:INTERNAL_TOKEN_SECRET')).toThrow(/not allowlisted/);
    expect(() => resolveCredential('env:S3_SECRET_ACCESS_KEY')).toThrow(/not allowlisted/);
  });

  it('rejects an unsupported scheme', () => {
    expect(() => resolveCredential('vault:gh')).toThrow(/Unsupported credentialRef scheme/);
  });
});

import { afterEach, describe, expect, it } from 'vitest';
import { isPrivateTarget, resolveGithubCredential } from './github.credential';

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
});

describe('resolveGithubCredential', () => {
  it('returns undefined when the ref is null', () => {
    expect(resolveGithubCredential(null)).toBeUndefined();
  });

  it('reads an allowlisted GITHUB_* env var', () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    expect(resolveGithubCredential('env:GITHUB_TOKEN')).toBe('ghp_test');
  });

  it('refuses env:DATABASE_URL', () => {
    expect(() => resolveGithubCredential('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });

  it('rejects an unsupported scheme', () => {
    expect(() => resolveGithubCredential('vault:gh')).toThrow(/Unsupported credentialRef scheme/);
  });
});

describe('isPrivateTarget', () => {
  it('treats private / visibility=private as private', () => {
    expect(isPrivateTarget({ private: true })).toBe(true);
    expect(isPrivateTarget({ visibility: 'private' })).toBe(true);
    expect(isPrivateTarget({ exposure: 'internal' })).toBe(false);
  });
});

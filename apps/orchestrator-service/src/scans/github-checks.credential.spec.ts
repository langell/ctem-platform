import { afterEach, describe, expect, it } from 'vitest';
import {
  CHECKS_DEFAULT_CREDENTIAL_REF,
  isGithubEnvRef,
  requireGithubToken,
  resolveChecksGithubToken,
} from './github-checks.credential';

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
  delete process.env.GITHUB_CHECKS_TOKEN;
  delete process.env.GITLAB_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.DATABASE_URL;
});

describe('GitHub Checks credentials', () => {
  it('accepts only env:GITHUB_* refs', () => {
    expect(isGithubEnvRef('env:GITHUB_TOKEN')).toBe(true);
    expect(isGithubEnvRef('env:GITHUB_CHECKS_TOKEN')).toBe(true);
    expect(isGithubEnvRef('env:GITLAB_TOKEN')).toBe(false);
    expect(isGithubEnvRef('env:AWS_ACCESS_KEY_ID')).toBe(false);
    expect(isGithubEnvRef('env:DATABASE_URL')).toBe(false);
    expect(isGithubEnvRef(null)).toBe(false);
  });

  it('fails closed when the pointed GITHUB_* env var is empty', () => {
    expect(() => requireGithubToken('env:GITHUB_TOKEN')).toThrow(/cannot be used/);
  });

  it('does not read DATABASE_URL when resolving Checks credentials', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    process.env.GITHUB_TOKEN = 'ghp_test';
    expect(resolveChecksGithubToken(['env:DATABASE_URL']).ok).toBe(true);
    if (resolveChecksGithubToken(['env:DATABASE_URL']).ok) {
      expect(resolveChecksGithubToken(['env:DATABASE_URL']).ref).toBe(CHECKS_DEFAULT_CREDENTIAL_REF);
    }
  });

  it('prefers a usable scan/asset GITHUB_* ref over the platform default', () => {
    process.env.GITHUB_TOKEN = 'ghp_default';
    process.env.GITHUB_CHECKS_TOKEN = 'ghp_integration';
    const picked = resolveChecksGithubToken(['env:GITLAB_TOKEN', 'env:GITHUB_CHECKS_TOKEN']);
    expect(picked).toEqual({ ok: true, token: 'ghp_integration', ref: 'env:GITHUB_CHECKS_TOKEN' });
  });

  it('does not fall back when a GITHUB_* integration ref is unusable', () => {
    process.env.GITHUB_TOKEN = 'ghp_default';
    const picked = resolveChecksGithubToken(['env:GITHUB_CHECKS_TOKEN']);
    expect(picked.ok).toBe(false);
  });
});

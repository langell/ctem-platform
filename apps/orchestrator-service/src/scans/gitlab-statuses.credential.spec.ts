import { afterEach, describe, expect, it } from 'vitest';
import {
  STATUSES_DEFAULT_CREDENTIAL_REF,
  isGitlabEnvRef,
  requireGitlabToken,
  resolveStatusesGitlabToken,
} from './gitlab-statuses.credential';

afterEach(() => {
  delete process.env.GITLAB_TOKEN;
  delete process.env.GITLAB_INT_TOKEN;
  delete process.env.GITHUB_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.DATABASE_URL;
});

describe('GitLab Commit Status credentials', () => {
  it('accepts only env:GITLAB_* refs', () => {
    expect(isGitlabEnvRef('env:GITLAB_TOKEN')).toBe(true);
    expect(isGitlabEnvRef('env:GITLAB_INT_TOKEN')).toBe(true);
    expect(isGitlabEnvRef('env:GITHUB_TOKEN')).toBe(false);
    expect(isGitlabEnvRef('env:AWS_ACCESS_KEY_ID')).toBe(false);
    expect(isGitlabEnvRef('env:DATABASE_URL')).toBe(false);
    expect(isGitlabEnvRef(null)).toBe(false);
  });

  it('fails closed when the pointed GITLAB_* env var is empty', () => {
    expect(() => requireGitlabToken('env:GITLAB_TOKEN')).toThrow(/cannot be used/);
  });

  it('does not read DATABASE_URL when resolving status credentials', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    process.env.GITLAB_TOKEN = 'glpat-test';
    expect(resolveStatusesGitlabToken(['env:DATABASE_URL']).ok).toBe(true);
    if (resolveStatusesGitlabToken(['env:DATABASE_URL']).ok) {
      expect(resolveStatusesGitlabToken(['env:DATABASE_URL']).ref).toBe(STATUSES_DEFAULT_CREDENTIAL_REF);
    }
  });

  it('prefers a usable scan/asset GITLAB_* ref over the platform default', () => {
    process.env.GITLAB_TOKEN = 'glpat-default';
    process.env.GITLAB_INT_TOKEN = 'glpat-integration';
    const picked = resolveStatusesGitlabToken(['env:GITHUB_TOKEN', 'env:GITLAB_INT_TOKEN']);
    expect(picked).toEqual({ ok: true, token: 'glpat-integration', ref: 'env:GITLAB_INT_TOKEN' });
  });

  it('does not fall back when a GITLAB_* integration ref is unusable', () => {
    process.env.GITLAB_TOKEN = 'glpat-default';
    const picked = resolveStatusesGitlabToken(['env:GITLAB_INT_TOKEN']);
    expect(picked.ok).toBe(false);
  });
});

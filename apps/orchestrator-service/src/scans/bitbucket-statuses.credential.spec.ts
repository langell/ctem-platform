import { afterEach, describe, expect, it } from 'vitest';
import {
  STATUSES_DEFAULT_CREDENTIAL_REF,
  isBitbucketEnvRef,
  requireBitbucketToken,
  resolveStatusesBitbucketToken,
} from './bitbucket-statuses.credential';

afterEach(() => {
  delete process.env.BITBUCKET_TOKEN;
  delete process.env.BITBUCKET_INT_TOKEN;
  delete process.env.GITHUB_TOKEN;
  delete process.env.GITLAB_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.DATABASE_URL;
});

describe('Bitbucket build-status credentials', () => {
  it('accepts only env:BITBUCKET_* refs', () => {
    expect(isBitbucketEnvRef('env:BITBUCKET_TOKEN')).toBe(true);
    expect(isBitbucketEnvRef('env:BITBUCKET_INT_TOKEN')).toBe(true);
    expect(isBitbucketEnvRef('env:GITHUB_TOKEN')).toBe(false);
    expect(isBitbucketEnvRef('env:GITLAB_TOKEN')).toBe(false);
    expect(isBitbucketEnvRef('env:AWS_ACCESS_KEY_ID')).toBe(false);
    expect(isBitbucketEnvRef('env:DATABASE_URL')).toBe(false);
    expect(isBitbucketEnvRef(null)).toBe(false);
  });

  it('fails closed when the pointed BITBUCKET_* env var is empty', () => {
    expect(() => requireBitbucketToken('env:BITBUCKET_TOKEN')).toThrow(/cannot be used/);
  });

  it('does not read DATABASE_URL when resolving status credentials', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    process.env.BITBUCKET_TOKEN = 'bb-test';
    const picked = resolveStatusesBitbucketToken(['env:DATABASE_URL']);
    expect(picked).toEqual({ ok: true, token: 'bb-test', ref: STATUSES_DEFAULT_CREDENTIAL_REF });
  });

  it('prefers a usable scan/asset BITBUCKET_* ref over the platform default', () => {
    process.env.BITBUCKET_TOKEN = 'bb-default';
    process.env.BITBUCKET_INT_TOKEN = 'bb-integration';
    const picked = resolveStatusesBitbucketToken([
      'env:GITHUB_TOKEN',
      'env:GITLAB_TOKEN',
      'env:BITBUCKET_INT_TOKEN',
    ]);
    expect(picked).toEqual({ ok: true, token: 'bb-integration', ref: 'env:BITBUCKET_INT_TOKEN' });
  });

  it('does not fall back when a BITBUCKET_* integration ref is unusable', () => {
    process.env.BITBUCKET_TOKEN = 'bb-default';
    const picked = resolveStatusesBitbucketToken(['env:BITBUCKET_INT_TOKEN']);
    expect(picked.ok).toBe(false);
  });
});

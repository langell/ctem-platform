import { afterEach, describe, expect, it } from 'vitest';
import { requireAwsCredentials, resolveCredential } from './credentials';

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
  delete process.env.GITHUB_TEST_TOKEN;
  delete process.env.GITLAB_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.AWS_SESSION_TOKEN;
  delete process.env.AWS_TEST_TOKEN;
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

  it('reads an allowlisted AWS_* env var', () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    expect(resolveCredential('env:AWS_ACCESS_KEY_ID')).toBe('AKIATEST');
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

describe('requireAwsCredentials', () => {
  it('fails closed when credentialRef is missing', () => {
    expect(() => requireAwsCredentials(null)).toThrow(/env:AWS_\*/);
  });

  it('fails closed when the pointed AWS_* env var is empty', () => {
    expect(() => requireAwsCredentials('env:AWS_ACCESS_KEY_ID')).toThrow(/cannot be used/);
  });

  it('fails closed when the signing pair is incomplete', () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    expect(() => requireAwsCredentials('env:AWS_ACCESS_KEY_ID')).toThrow(
      /AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY/,
    );
  });

  it('refuses a GITHUB_* ref even when AWS keys are present', () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    process.env.AWS_SECRET_ACCESS_KEY = 'secret';
    expect(() => requireAwsCredentials('env:GITHUB_TOKEN')).toThrow(/env:AWS_\*/);
  });

  it('refuses env:DATABASE_URL without reading the secret', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => requireAwsCredentials('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });

  it('returns the platform pair when the ref and both keys are set', () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    process.env.AWS_SECRET_ACCESS_KEY = 'secret';
    expect(requireAwsCredentials('env:AWS_ACCESS_KEY_ID')).toEqual({
      accessKeyId: 'AKIATEST',
      secretAccessKey: 'secret',
    });
  });
});

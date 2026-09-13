import { afterEach, describe, expect, it } from 'vitest';
import {
  optionalGithubToken,
  requireAwsCredentials,
  requireGithubToken,
} from './container.credential';

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.AWS_SESSION_TOKEN;
});

describe('requireGithubToken', () => {
  it('fails closed when credentialRef is missing or empty', () => {
    expect(() => requireGithubToken(null)).toThrow(/env:GITHUB_\*/);
    expect(() => requireGithubToken('env:GITHUB_TOKEN')).toThrow(/cannot be used/);
  });

  it('refuses an AWS_* ref even when a GITHUB_TOKEN is present', () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    expect(() => requireGithubToken('env:AWS_ACCESS_KEY_ID')).toThrow(/env:GITHUB_\*/);
  });

  it('refuses env:DATABASE_URL without reading the secret', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => requireGithubToken('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });

  it('returns the token when the ref points at a usable GITHUB_* name', () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    expect(requireGithubToken('env:GITHUB_TOKEN')).toBe('ghp_test');
    expect(optionalGithubToken(null)).toBeUndefined();
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

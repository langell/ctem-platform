import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { requireAwsCredentials, requireGcpCredentials, resolveCredential } from './credentials';

const gcpPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
  delete process.env.GITHUB_TEST_TOKEN;
  delete process.env.GITLAB_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.AWS_SESSION_TOKEN;
  delete process.env.AWS_TEST_TOKEN;
  delete process.env.GCP_CLIENT_EMAIL;
  delete process.env.GCP_PRIVATE_KEY;
  delete process.env.GCP_TEST_TOKEN;
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

  it('reads an allowlisted GCP_* env var', () => {
    process.env.GCP_CLIENT_EMAIL = 'ctem@acme-prod.iam.gserviceaccount.com';
    expect(resolveCredential('env:GCP_CLIENT_EMAIL')).toBe('ctem@acme-prod.iam.gserviceaccount.com');
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

describe('requireGcpCredentials', () => {
  it('fails closed when credentialRef is missing', () => {
    expect(() => requireGcpCredentials(null)).toThrow(/env:GCP_\*/);
  });

  it('fails closed when the pointed GCP_* env var is empty', () => {
    expect(() => requireGcpCredentials('env:GCP_CLIENT_EMAIL')).toThrow(/cannot be used/);
  });

  it('fails closed when the signing pair is incomplete', () => {
    process.env.GCP_CLIENT_EMAIL = 'ctem@acme-prod.iam.gserviceaccount.com';
    expect(() => requireGcpCredentials('env:GCP_CLIENT_EMAIL')).toThrow(
      /GCP_CLIENT_EMAIL and GCP_PRIVATE_KEY/,
    );
  });

  it('fails closed when GCP_PRIVATE_KEY is unusable', () => {
    process.env.GCP_CLIENT_EMAIL = 'ctem@acme-prod.iam.gserviceaccount.com';
    process.env.GCP_PRIVATE_KEY = 'not-a-pem';
    expect(() => requireGcpCredentials('env:GCP_CLIENT_EMAIL')).toThrow(/unusable/);
  });

  it('refuses an AWS_* ref even when GCP keys are present', () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    process.env.GCP_CLIENT_EMAIL = 'ctem@acme-prod.iam.gserviceaccount.com';
    process.env.GCP_PRIVATE_KEY = gcpPem;
    expect(() => requireGcpCredentials('env:AWS_ACCESS_KEY_ID')).toThrow(/env:GCP_\*/);
  });

  it('refuses env:DATABASE_URL without reading the secret', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => requireGcpCredentials('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });

  it('returns the platform pair when the ref and both keys are set', () => {
    process.env.GCP_CLIENT_EMAIL = 'ctem@acme-prod.iam.gserviceaccount.com';
    process.env.GCP_PRIVATE_KEY = gcpPem;
    expect(requireGcpCredentials('env:GCP_CLIENT_EMAIL')).toEqual({
      clientEmail: 'ctem@acme-prod.iam.gserviceaccount.com',
      privateKey: gcpPem,
    });
  });
});

import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import {
  requireAwsCredentials,
  requireAzureCredentials,
  requireGcpCredentials,
  requireGithubToken,
  resolveCredential,
} from './credentials';

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
  delete process.env.AZURE_TENANT_ID;
  delete process.env.AZURE_CLIENT_ID;
  delete process.env.AZURE_CLIENT_SECRET;
  delete process.env.AZURE_TEST_TOKEN;
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

  it('reads an allowlisted AZURE_* env var', () => {
    process.env.AZURE_TENANT_ID = '22222222-2222-2222-2222-222222222222';
    expect(resolveCredential('env:AZURE_TENANT_ID')).toBe('22222222-2222-2222-2222-222222222222');
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

describe('requireGithubToken', () => {
  it('fails closed when credentialRef is missing', () => {
    expect(() => requireGithubToken(null)).toThrow(/env:GITHUB_\*/);
  });

  it('fails closed when the pointed GITHUB_* env var is empty', () => {
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

describe('requireAzureCredentials', () => {
  const tenant = '22222222-2222-2222-2222-222222222222';
  const client = '33333333-3333-3333-3333-333333333333';

  function setAzureTriple(): void {
    process.env.AZURE_TENANT_ID = tenant;
    process.env.AZURE_CLIENT_ID = client;
    process.env.AZURE_CLIENT_SECRET = 'super-secret';
  }

  it('fails closed when credentialRef is missing', () => {
    expect(() => requireAzureCredentials(null)).toThrow(/env:AZURE_\*/);
  });

  it('fails closed when the pointed AZURE_* env var is empty', () => {
    expect(() => requireAzureCredentials('env:AZURE_CLIENT_ID')).toThrow(/cannot be used/);
  });

  it('fails closed when the client-credentials triple is incomplete', () => {
    process.env.AZURE_TENANT_ID = tenant;
    process.env.AZURE_CLIENT_ID = client;
    expect(() => requireAzureCredentials('env:AZURE_CLIENT_ID')).toThrow(
      /AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET/,
    );
  });

  it('fails closed when AZURE_TENANT_ID is unusable', () => {
    process.env.AZURE_TENANT_ID = 'https://evil.example';
    process.env.AZURE_CLIENT_ID = client;
    process.env.AZURE_CLIENT_SECRET = 'super-secret';
    expect(() => requireAzureCredentials('env:AZURE_TENANT_ID')).toThrow(/unusable/);
  });

  it('fails closed when AZURE_CLIENT_ID is unusable', () => {
    process.env.AZURE_TENANT_ID = tenant;
    process.env.AZURE_CLIENT_ID = 'not-a-guid';
    process.env.AZURE_CLIENT_SECRET = 'super-secret';
    expect(() => requireAzureCredentials('env:AZURE_CLIENT_ID')).toThrow(/unusable/);
  });

  it('refuses a GITHUB_* ref even when Azure keys are present', () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    setAzureTriple();
    expect(() => requireAzureCredentials('env:GITHUB_TOKEN')).toThrow(/env:AZURE_\*/);
  });

  it('refuses an AWS_* ref even when Azure keys are present', () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    setAzureTriple();
    expect(() => requireAzureCredentials('env:AWS_ACCESS_KEY_ID')).toThrow(/env:AZURE_\*/);
  });

  it('refuses a GCP_* ref even when Azure keys are present', () => {
    process.env.GCP_CLIENT_EMAIL = 'ctem@acme-prod.iam.gserviceaccount.com';
    setAzureTriple();
    expect(() => requireAzureCredentials('env:GCP_CLIENT_EMAIL')).toThrow(/env:AZURE_\*/);
  });

  it('refuses env:DATABASE_URL without reading the secret', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => requireAzureCredentials('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });

  it('returns the platform triple when the ref and all three keys are set', () => {
    setAzureTriple();
    expect(requireAzureCredentials('env:AZURE_CLIENT_ID')).toEqual({
      tenantId: tenant,
      clientId: client,
      clientSecret: 'super-secret',
    });
  });
});

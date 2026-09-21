import { afterEach, describe, expect, it } from 'vitest';
import {
  optionalGithubToken,
  requireAwsCredentials,
  requireAzureCredentials,
  requireDockerhubCredentials,
  requireGcpCredentials,
  requireGithubToken,
  requireQuayToken,
} from './container.credential';
import { generateKeyPairSync } from 'node:crypto';

const gcpPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.AWS_SESSION_TOKEN;
  delete process.env.GCP_CLIENT_EMAIL;
  delete process.env.GCP_PRIVATE_KEY;
  delete process.env.AZURE_TENANT_ID;
  delete process.env.AZURE_CLIENT_ID;
  delete process.env.AZURE_CLIENT_SECRET;
  delete process.env.DOCKERHUB_USERNAME;
  delete process.env.DOCKERHUB_TOKEN;
  delete process.env.QUAY_TOKEN;
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

  it('refuses a GITHUB_* ref even when GCP keys are present', () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    process.env.GCP_CLIENT_EMAIL = 'ctem@acme-prod.iam.gserviceaccount.com';
    process.env.GCP_PRIVATE_KEY = gcpPem;
    expect(() => requireGcpCredentials('env:GITHUB_TOKEN')).toThrow(/env:GCP_\*/);
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

const AZURE_TENANT = '22222222-2222-2222-2222-222222222222';
const AZURE_CLIENT = '33333333-3333-3333-3333-333333333333';

describe('requireAzureCredentials', () => {
  it('fails closed when credentialRef is missing', () => {
    expect(() => requireAzureCredentials(null)).toThrow(/env:AZURE_\*/);
  });

  it('fails closed when the pointed AZURE_* env var is empty', () => {
    expect(() => requireAzureCredentials('env:AZURE_CLIENT_ID')).toThrow(/cannot be used/);
  });

  it('fails closed when the client-credentials triple is incomplete', () => {
    process.env.AZURE_TENANT_ID = AZURE_TENANT;
    process.env.AZURE_CLIENT_ID = AZURE_CLIENT;
    expect(() => requireAzureCredentials('env:AZURE_CLIENT_ID')).toThrow(
      /AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET/,
    );
  });

  it('fails closed when AZURE_TENANT_ID is unusable', () => {
    process.env.AZURE_TENANT_ID = 'https://evil.example';
    process.env.AZURE_CLIENT_ID = AZURE_CLIENT;
    process.env.AZURE_CLIENT_SECRET = 'super-secret';
    expect(() => requireAzureCredentials('env:AZURE_CLIENT_ID')).toThrow(/unusable/);
  });

  it('fails closed when AZURE_CLIENT_ID is unusable', () => {
    process.env.AZURE_TENANT_ID = AZURE_TENANT;
    process.env.AZURE_CLIENT_ID = 'not-a-guid';
    process.env.AZURE_CLIENT_SECRET = 'super-secret';
    expect(() => requireAzureCredentials('env:AZURE_CLIENT_ID')).toThrow(/unusable/);
  });

  it('refuses a GITHUB_* ref even when AZURE keys are present', () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    process.env.AZURE_TENANT_ID = AZURE_TENANT;
    process.env.AZURE_CLIENT_ID = AZURE_CLIENT;
    process.env.AZURE_CLIENT_SECRET = 'super-secret';
    expect(() => requireAzureCredentials('env:GITHUB_TOKEN')).toThrow(/env:AZURE_\*/);
  });

  it('refuses env:DATABASE_URL without reading the secret', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => requireAzureCredentials('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });

  it('returns the platform triple when the ref and all three values are set', () => {
    process.env.AZURE_TENANT_ID = AZURE_TENANT;
    process.env.AZURE_CLIENT_ID = AZURE_CLIENT;
    process.env.AZURE_CLIENT_SECRET = 'super-secret';
    expect(requireAzureCredentials('env:AZURE_CLIENT_ID')).toEqual({
      tenantId: AZURE_TENANT,
      clientId: AZURE_CLIENT,
      clientSecret: 'super-secret',
    });
  });
});

describe('requireDockerhubCredentials', () => {
  function setDockerhubPair(): void {
    process.env.DOCKERHUB_USERNAME = 'acme';
    process.env.DOCKERHUB_TOKEN = 'dckr_pat_test';
  }

  it('fails closed when credentialRef is missing', () => {
    expect(() => requireDockerhubCredentials(null)).toThrow(/env:DOCKERHUB_\*/);
  });

  it('fails closed when the pointed DOCKERHUB_* env var is empty', () => {
    expect(() => requireDockerhubCredentials('env:DOCKERHUB_TOKEN')).toThrow(/cannot be used/);
  });

  it('fails closed when the username/token pair is incomplete', () => {
    process.env.DOCKERHUB_USERNAME = 'acme';
    expect(() => requireDockerhubCredentials('env:DOCKERHUB_USERNAME')).toThrow(
      /DOCKERHUB_USERNAME and DOCKERHUB_TOKEN/,
    );
  });

  it('fails closed when DOCKERHUB_USERNAME is unusable', () => {
    process.env.DOCKERHUB_USERNAME = 'https://evil.example';
    process.env.DOCKERHUB_TOKEN = 'dckr_pat_test';
    expect(() => requireDockerhubCredentials('env:DOCKERHUB_USERNAME')).toThrow(/unusable/);
  });

  it('fails closed when DOCKERHUB_USERNAME is a docker.io host id', () => {
    process.env.DOCKERHUB_USERNAME = 'registry-1.docker.io';
    process.env.DOCKERHUB_TOKEN = 'dckr_pat_test';
    expect(() => requireDockerhubCredentials('env:DOCKERHUB_USERNAME')).toThrow(/unusable/);
  });

  it('refuses a GITHUB_* ref even when Docker Hub keys are present', () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    setDockerhubPair();
    expect(() => requireDockerhubCredentials('env:GITHUB_TOKEN')).toThrow(/env:DOCKERHUB_\*/);
  });

  it('refuses an AWS_* ref even when Docker Hub keys are present', () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    setDockerhubPair();
    expect(() => requireDockerhubCredentials('env:AWS_ACCESS_KEY_ID')).toThrow(/env:DOCKERHUB_\*/);
  });

  it('refuses env:DATABASE_URL without reading the secret', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => requireDockerhubCredentials('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });

  it('returns the platform pair when the ref and both keys are set', () => {
    setDockerhubPair();
    expect(requireDockerhubCredentials('env:DOCKERHUB_TOKEN')).toEqual({
      username: 'acme',
      token: 'dckr_pat_test',
    });
  });
});

describe('requireQuayToken', () => {
  it('fails closed when credentialRef is missing', () => {
    expect(() => requireQuayToken(null)).toThrow(/env:QUAY_\*/);
  });

  it('fails closed when the pointed QUAY_* env var is empty', () => {
    expect(() => requireQuayToken('env:QUAY_TOKEN')).toThrow(/cannot be used/);
  });

  it('refuses a GITHUB_* ref even when a QUAY_TOKEN is present', () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    process.env.QUAY_TOKEN = 'quay_test';
    expect(() => requireQuayToken('env:GITHUB_TOKEN')).toThrow(/env:QUAY_\*/);
  });

  it('refuses a DOCKERHUB_* ref even when a QUAY_TOKEN is present', () => {
    process.env.DOCKERHUB_TOKEN = 'dckr_pat_test';
    process.env.QUAY_TOKEN = 'quay_test';
    expect(() => requireQuayToken('env:DOCKERHUB_TOKEN')).toThrow(/env:QUAY_\*/);
  });

  it('refuses an AWS_* ref even when a QUAY_TOKEN is present', () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    process.env.QUAY_TOKEN = 'quay_test';
    expect(() => requireQuayToken('env:AWS_ACCESS_KEY_ID')).toThrow(/env:QUAY_\*/);
  });

  it('refuses env:DATABASE_URL without reading the secret', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => requireQuayToken('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });

  it('returns the token when the ref points at a usable QUAY_* name', () => {
    process.env.QUAY_TOKEN = 'quay_test';
    expect(requireQuayToken('env:QUAY_TOKEN')).toBe('quay_test');
  });
});

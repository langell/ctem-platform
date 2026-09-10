import { afterEach, describe, expect, it } from 'vitest';
import {
  CspmCredentialError,
  requireAwsCredentials,
  requireAzureCredentials,
  requireGcpCredentials,
  resolveCredential,
} from './credentials';

afterEach(() => {
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.GCP_CLIENT_EMAIL;
  delete process.env.GCP_PRIVATE_KEY;
  delete process.env.AZURE_TENANT_ID;
  delete process.env.AZURE_CLIENT_ID;
  delete process.env.AZURE_CLIENT_SECRET;
});

describe('resolveCredential', () => {
  it('refuses env:DATABASE_URL instead of reading it', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => resolveCredential('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });
});

describe('requireAwsCredentials', () => {
  it('fails closed when credentialRef is missing', () => {
    expect(() => requireAwsCredentials(null)).toThrow(CspmCredentialError);
    expect(() => requireAwsCredentials(null)).toThrow(/env:AWS_/);
  });

  it('fails closed when the pointed AWS_* env var is empty', () => {
    expect(() => requireAwsCredentials('env:AWS_ACCESS_KEY_ID')).toThrow(/cannot be used/);
  });

  it('refuses env:DATABASE_URL without reading the secret', () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    expect(() => requireAwsCredentials('env:DATABASE_URL')).toThrow(/not allowlisted/);
  });
});

describe('requireGcpCredentials', () => {
  it('fails closed when credentialRef is missing', () => {
    expect(() => requireGcpCredentials(null)).toThrow(/env:GCP_/);
  });

  it('fails closed when GCP_PRIVATE_KEY is unusable', () => {
    process.env.GCP_CLIENT_EMAIL = 'ctem@acme-prod.iam.gserviceaccount.com';
    process.env.GCP_PRIVATE_KEY = 'not-a-pem';
    expect(() => requireGcpCredentials('env:GCP_CLIENT_EMAIL')).toThrow(/unusable/);
  });
});

describe('requireAzureCredentials', () => {
  it('fails closed when credentialRef is missing', () => {
    expect(() => requireAzureCredentials(null)).toThrow(/env:AZURE_/);
  });

  it('returns the platform triple when the ref and all three keys are set', () => {
    process.env.AZURE_TENANT_ID = '22222222-2222-2222-2222-222222222222';
    process.env.AZURE_CLIENT_ID = '33333333-3333-3333-3333-333333333333';
    process.env.AZURE_CLIENT_SECRET = 'super-secret';
    expect(requireAzureCredentials('env:AZURE_CLIENT_ID')).toEqual({
      tenantId: '22222222-2222-2222-2222-222222222222',
      clientId: '33333333-3333-3333-3333-333333333333',
      clientSecret: 'super-secret',
    });
  });
});

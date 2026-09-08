import { describe, expect, it } from 'vitest';
import {
  allowlistedEcrApiUrl,
  ecrApiUrl,
  isEcrApiHost,
  refuseTenantWritableEndpoint,
} from './ecr.egress';

describe('allowlistedEcrApiUrl', () => {
  it('accepts commercial and GovCloud ECR JSON API hosts', () => {
    expect(allowlistedEcrApiUrl('https://api.ecr.us-east-1.amazonaws.com/')).toBe(
      'https://api.ecr.us-east-1.amazonaws.com/',
    );
    expect(allowlistedEcrApiUrl('https://api.ecr.us-gov-west-1.amazonaws.com/')).toBe(
      'https://api.ecr.us-gov-west-1.amazonaws.com/',
    );
  });

  it('refuses dkr.ecr (layer pull) and other non-ECR API hosts', () => {
    expect(() =>
      allowlistedEcrApiUrl('https://123456789012.dkr.ecr.us-east-1.amazonaws.com/v2/'),
    ).toThrow(/only api\.ecr/);
    expect(() => allowlistedEcrApiUrl('https://ecr.us-east-1.amazonaws.com/')).toThrow(
      /only api\.ecr/,
    );
    expect(() => allowlistedEcrApiUrl('https://evil.example/ecr')).toThrow(/only amazonaws\.com/);
  });

  it('refuses suffix-confusion and lookalike hosts', () => {
    expect(() =>
      allowlistedEcrApiUrl('https://api.ecr.us-east-1.amazonaws.com.evil.example/'),
    ).toThrow(/only amazonaws\.com/);
    expect(() => allowlistedEcrApiUrl('https://api.ecr.us-east-1.evilamazonaws.com/')).toThrow(
      /only amazonaws\.com/,
    );
  });

  it('refuses http, userinfo, and non-default ports', () => {
    expect(() => allowlistedEcrApiUrl('http://api.ecr.us-east-1.amazonaws.com/')).toThrow(
      /non-https/,
    );
    expect(() =>
      allowlistedEcrApiUrl('https://user:pass@api.ecr.us-east-1.amazonaws.com/'),
    ).toThrow(/userinfo/);
    expect(() => allowlistedEcrApiUrl('https://api.ecr.us-east-1.amazonaws.com:8443/')).toThrow(
      /port/,
    );
  });
});

describe('isEcrApiHost', () => {
  it('accepts api.ecr.{region}.amazonaws.com only', () => {
    expect(isEcrApiHost('api.ecr.us-east-1.amazonaws.com')).toBe(true);
    expect(isEcrApiHost('api.ecr.us-gov-west-1.amazonaws.com')).toBe(true);
    expect(isEcrApiHost('API.ECR.US-EAST-1.AMAZONAWS.COM')).toBe(true);
    expect(isEcrApiHost('123456789012.dkr.ecr.us-east-1.amazonaws.com')).toBe(false);
    expect(isEcrApiHost('ecr.us-east-1.amazonaws.com')).toBe(false);
    expect(isEcrApiHost('api.ecr.us-east-1.amazonaws.com.evil.example')).toBe(false);
    expect(isEcrApiHost('s3.amazonaws.com')).toBe(false);
  });
});

describe('ecrApiUrl', () => {
  it('builds the regional JSON API host from a region id', () => {
    expect(ecrApiUrl('eu-central-1')).toBe('https://api.ecr.eu-central-1.amazonaws.com/');
    expect(ecrApiUrl('us-gov-east-1')).toBe('https://api.ecr.us-gov-east-1.amazonaws.com/');
  });

  it('refuses a region that is not an AWS region identifier', () => {
    expect(() => ecrApiUrl('us-east-1.evil.example')).toThrow(/region/);
    expect(() => ecrApiUrl('https://evil.example')).toThrow(/region/);
  });
});

describe('refuseTenantWritableEndpoint', () => {
  it('allows a region-only config', () => {
    expect(() => refuseTenantWritableEndpoint({ region: 'us-east-1' })).not.toThrow();
  });

  it('refuses tenant-writable endpoint keys including registry/ecr hosts', () => {
    expect(() =>
      refuseTenantWritableEndpoint({ region: 'us-east-1', endpoint: 'https://evil.example' }),
    ).toThrow(/tenant-writable ECR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        region: 'us-east-1',
        registryUrl: 'https://123.dkr.ecr.us-east-1.amazonaws.com',
      }),
    ).toThrow(/tenant-writable ECR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        region: 'us-east-1',
        ecrUrl: 'https://api.ecr.us-east-1.amazonaws.com',
      }),
    ).toThrow(/tenant-writable ECR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ region: 'us-east-1', host: 'evil.example' }),
    ).toThrow(/tenant-writable ECR endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({
        region: 'us-east-1',
        customEndpoint: 'https://api.ecr.us-east-1.amazonaws.com.evil.example',
      }),
    ).toThrow(/tenant-writable ECR endpoint/);
  });

  it('refuses a region that is itself a URL', () => {
    expect(() => refuseTenantWritableEndpoint({ region: 'https://evil.example' })).toThrow(
      /tenant-writable ECR endpoint/,
    );
  });
});

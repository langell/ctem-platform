import { describe, expect, it } from 'vitest';
import {
  allowlistedAwsUrl,
  awsServiceUrl,
  isAwsApiHost,
  refuseTenantWritableEndpoint,
} from './aws.egress';

describe('allowlistedAwsUrl', () => {
  it('accepts commercial AWS API hosts', () => {
    expect(allowlistedAwsUrl('https://ec2.us-east-1.amazonaws.com/')).toBe(
      'https://ec2.us-east-1.amazonaws.com/',
    );
    expect(allowlistedAwsUrl('https://sts.us-west-2.amazonaws.com/')).toBe(
      'https://sts.us-west-2.amazonaws.com/',
    );
    expect(allowlistedAwsUrl('https://s3.amazonaws.com/')).toBe('https://s3.amazonaws.com/');
  });

  it('refuses a tenant-writable host', () => {
    expect(() => allowlistedAwsUrl('https://evil.example/aws')).toThrow(/only amazonaws\.com/);
  });

  it('refuses suffix-confusion and lookalike hosts', () => {
    expect(() =>
      allowlistedAwsUrl('https://ec2.us-east-1.amazonaws.com.evil.example/'),
    ).toThrow(/only amazonaws\.com/);
    expect(() => allowlistedAwsUrl('https://evilamazonaws.com/')).toThrow(/only amazonaws\.com/);
    expect(() => allowlistedAwsUrl('https://amazonaws.com.evil.example/')).toThrow(
      /only amazonaws\.com/,
    );
  });

  it('refuses http, userinfo, and non-default ports', () => {
    expect(() => allowlistedAwsUrl('http://ec2.us-east-1.amazonaws.com/')).toThrow(/non-https/);
    expect(() => allowlistedAwsUrl('https://user:pass@ec2.us-east-1.amazonaws.com/')).toThrow(
      /userinfo/,
    );
    expect(() => allowlistedAwsUrl('https://ec2.us-east-1.amazonaws.com:8443/')).toThrow(/port/);
  });
});

describe('isAwsApiHost', () => {
  it('accepts amazonaws.com and its subdomains only', () => {
    expect(isAwsApiHost('s3.amazonaws.com')).toBe(true);
    expect(isAwsApiHost('ec2.us-east-1.amazonaws.com')).toBe(true);
    expect(isAwsApiHost('amazonaws.com')).toBe(true);
    expect(isAwsApiHost('evil.example')).toBe(false);
    expect(isAwsApiHost('amazonaws.com.evil.example')).toBe(false);
  });
});

describe('awsServiceUrl', () => {
  it('derives regional EC2/STS hosts and the global S3 list host', () => {
    expect(awsServiceUrl('ec2', 'us-east-1')).toBe('https://ec2.us-east-1.amazonaws.com/');
    expect(awsServiceUrl('sts', 'eu-central-1')).toBe('https://sts.eu-central-1.amazonaws.com/');
    expect(awsServiceUrl('s3', 'ap-southeast-2')).toBe('https://s3.amazonaws.com/');
  });

  it('refuses a region that is not an AWS region identifier', () => {
    expect(() => awsServiceUrl('ec2', 'us-east-1.evil.example')).toThrow(/region/);
    expect(() => awsServiceUrl('ec2', 'https://evil.example')).toThrow(/region/);
  });
});

describe('refuseTenantWritableEndpoint', () => {
  it('allows a region-only config', () => {
    expect(() => refuseTenantWritableEndpoint({ region: 'us-east-1' })).not.toThrow();
  });

  it('refuses tenant-writable endpoint keys', () => {
    expect(() =>
      refuseTenantWritableEndpoint({ region: 'us-east-1', endpoint: 'https://evil.example' }),
    ).toThrow(/tenant-writable AWS endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ region: 'us-east-1', apiUrl: 'https://evil.example/aws' }),
    ).toThrow(/tenant-writable AWS endpoint/);
    expect(() =>
      refuseTenantWritableEndpoint({ region: 'us-east-1', host: 'evil.example' }),
    ).toThrow(/tenant-writable AWS endpoint/);
  });

  it('refuses a region that is itself a URL', () => {
    expect(() => refuseTenantWritableEndpoint({ region: 'https://evil.example' })).toThrow(
      /tenant-writable AWS endpoint/,
    );
  });
});

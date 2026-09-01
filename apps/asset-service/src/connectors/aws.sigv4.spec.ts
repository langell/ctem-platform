import { describe, expect, it } from 'vitest';
import { allowlistedAwsUrl } from './aws.egress';
import { amzDate, sha256Hex, signAwsRequest } from './aws.sigv4';

const creds = {
  accessKeyId: 'AKIDEXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
};

describe('signAwsRequest', () => {
  it('signs an allowlisted AWS URL and never rewrites the host', () => {
    const now = new Date('2015-08-30T12:36:00.000Z');
    const signed = signAwsRequest({
      method: 'GET',
      url: 'https://s3.amazonaws.com/',
      region: 'us-east-1',
      service: 's3',
      credentials: creds,
      now,
    });
    expect(signed.url).toBe('https://s3.amazonaws.com/');
    expect(signed.headers.host).toBe('s3.amazonaws.com');
    expect(signed.headers['x-amz-date']).toBe(amzDate(now));
    expect(signed.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//);
    expect(signed.headers.authorization).toContain('SignedHeaders=');
    expect(signed.headers.authorization).toContain('Signature=');
    expect(signed.headers['x-amz-content-sha256']).toBe(sha256Hex(''));
  });

  it('refuses to sign a tenant-writable host', () => {
    expect(() =>
      signAwsRequest({
        method: 'POST',
        url: 'https://evil.example/',
        region: 'us-east-1',
        service: 'ec2',
        credentials: creds,
      }),
    ).toThrow(/only amazonaws\.com/);
  });

  it('includes a session token header when present', () => {
    const signed = signAwsRequest({
      method: 'POST',
      url: allowlistedAwsUrl('https://ec2.us-east-1.amazonaws.com/'),
      region: 'us-east-1',
      service: 'ec2',
      credentials: { ...creds, sessionToken: 'session-token' },
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'Action=DescribeInstances',
      now: new Date('2015-08-30T12:36:00.000Z'),
    });
    expect(signed.headers['x-amz-security-token']).toBe('session-token');
    expect(signed.headers.authorization).toContain('x-amz-security-token');
  });
});

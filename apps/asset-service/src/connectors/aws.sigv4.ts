import { createHash, createHmac } from 'node:crypto';
import type { AwsCredentials } from './credentials';
import { allowlistedAwsUrl, type AwsService } from './aws.egress';

export interface SignAwsRequestInput {
  method: 'GET' | 'POST';
  url: string;
  region: string;
  service: AwsService;
  credentials: AwsCredentials;
  headers?: Record<string, string>;
  body?: string;
  now?: Date;
}

export interface SignedAwsRequest {
  url: string;
  method: 'GET' | 'POST';
  headers: Record<string, string>;
  body?: string;
}

/** AWS URI encode: unreserved chars stay; space is %20. */
export function awsUriEncode(value: string, encodeSlash = true): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) =>
    `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  ).replace(/%2F/g, encodeSlash ? '%2F' : '/');
}

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac('sha256', key).update(data).digest();
}

export function awsSigningKey(
  secret: string,
  dateStamp: string,
  region: string,
  service: string,
): Buffer {
  const kDate = hmac(`AWS4${secret}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

export function amzDate(now: Date): string {
  return now.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

/**
 * Sign a request for an already-allowlisted AWS URL. Re-runs the host
 * allowlist so a caller cannot bypass egress by handing a foreign URL here.
 */
export function signAwsRequest(input: SignAwsRequestInput): SignedAwsRequest {
  const url = new URL(allowlistedAwsUrl(input.url));
  const timestamp = amzDate(input.now ?? new Date());
  const dateStamp = timestamp.slice(0, 8);
  const body = input.body ?? '';
  const payloadHash = sha256Hex(body);

  const rawHeaders: Record<string, string> = {
    host: url.hostname,
    'x-amz-date': timestamp,
    'x-amz-content-sha256': payloadHash,
    ...normalizeHeaderNames(input.headers ?? {}),
  };
  if (input.credentials.sessionToken) {
    rawHeaders['x-amz-security-token'] = input.credentials.sessionToken;
  }

  const signedNames = Object.keys(rawHeaders).sort();
  const canonicalHeaders = signedNames.map((n) => `${n}:${rawHeaders[n]!.trim()}\n`).join('');
  const signedHeaders = signedNames.join(';');

  const canonicalQuery = [...url.searchParams.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${awsUriEncode(k)}=${awsUriEncode(v)}`)
    .join('&');

  const canonical = [
    input.method,
    url.pathname || '/',
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const scope = `${dateStamp}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', timestamp, scope, sha256Hex(canonical)].join('\n');
  const signature = hmac(awsSigningKey(input.credentials.secretAccessKey, dateStamp, input.region, input.service), stringToSign).toString(
    'hex',
  );

  rawHeaders.authorization =
    `AWS4-HMAC-SHA256 Credential=${input.credentials.accessKeyId}/${scope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    url: url.toString(),
    method: input.method,
    headers: rawHeaders,
    body: input.body,
  };
}

function normalizeHeaderNames(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k.toLowerCase()] = v;
  }
  return out;
}

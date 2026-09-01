import { describe, expect, it } from 'vitest';
import {
  assertNoOrgLeak,
  buildGatewayRequest,
  FORBIDDEN_ORG_KEYS,
  isForbiddenOrgKey,
} from './client';

describe('gateway client org scoping', () => {
  it('sends only Authorization — never an org header or query', () => {
    const req = buildGatewayRequest('/v1/findings', {
      token: 'jwt-for-org-a',
      query: { limit: 50, q: 'express' },
    });

    expect(req.headers.authorization).toBe('Bearer jwt-for-org-a');
    expect(Object.keys(req.headers).map((k) => k.toLowerCase())).not.toEqual(
      expect.arrayContaining(FORBIDDEN_ORG_KEYS),
    );
    expect(req.url).toBe('/v1/findings?limit=50&q=express');
    expect(req.url).not.toMatch(/org/i);
    expect(req.headers['x-ctem-org']).toBeUndefined();
  });

  it('refuses a client-supplied org query key', () => {
    expect(() =>
      buildGatewayRequest('/v1/findings', {
        token: 'jwt',
        query: { orgId: 'bbbbbbbb-2222-4333-8444-555566667777' },
      }),
    ).toThrow(/org selector/);
  });

  it('refuses org_id / x-ctem-org on the query string', () => {
    expect(() =>
      buildGatewayRequest('/v1/assets', { token: 'jwt', query: { org_id: 'other' } }),
    ).toThrow(/org selector/);
    expect(() =>
      buildGatewayRequest('/v1/session', { token: 'jwt', query: { 'x-ctem-org': 'other' } }),
    ).toThrow(/org selector/);
  });

  it('refuses an org field on a scan or login body', () => {
    expect(() =>
      buildGatewayRequest('/v1/scans', {
        method: 'POST',
        token: 'jwt',
        body: { scannerType: 'sca', orgId: 'other-org' },
      }),
    ).toThrow(/org selector/);
  });

  it('does not treat assetId as an org selector', () => {
    const req = buildGatewayRequest('/v1/findings', {
      token: 'jwt',
      query: { assetId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' },
    });
    expect(req.url).toContain('assetId=');
  });

  it('rejects non-gateway paths so the UI cannot aim at service ports', () => {
    expect(() => buildGatewayRequest('/internal/findings', { token: 'jwt' })).toThrow(/\/v1/);
    expect(() => buildGatewayRequest('http://localhost:3004/v1/findings', { token: 'jwt' })).toThrow(
      /\/v1/,
    );
  });

  it('assertNoOrgLeak flags the merge-bar headers', () => {
    expect(() =>
      assertNoOrgLeak({
        url: '/v1/findings',
        headers: { authorization: 'Bearer x', 'x-ctem-org': 'org-b' },
      }),
    ).toThrow(/header/);
    expect(isForbiddenOrgKey('X-Ctem-Org')).toBe(true);
    expect(isForbiddenOrgKey('limit')).toBe(false);
  });
});

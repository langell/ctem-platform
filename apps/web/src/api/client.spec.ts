import { describe, expect, it } from 'vitest';
import {
  assertNoOrgLeak,
  buildGatewayRequest,
  FORBIDDEN_ORG_KEYS,
  isForbiddenOrgKey,
  isPatToken,
  TOKEN_STORAGE_KEY,
  tokenStore,
} from './client';

function memoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear() {
      map.clear();
    },
    getItem(key) {
      return map.has(key) ? (map.get(key) as string) : null;
    },
    key(index) {
      return [...map.keys()][index] ?? null;
    },
    removeItem(key) {
      map.delete(key);
    },
    setItem(key, value) {
      map.set(key, String(value));
    },
  };
}

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

  it('sends policy writes to the gateway without an org selector', () => {
    const req = buildGatewayRequest('/v1/policies', {
      method: 'POST',
      token: 'jwt-for-org-a',
      body: {
        name: 'KEV notify',
        condition: { kevOnly: true },
        actions: ['fail_build'],
        priority: 10,
      },
    });
    expect(req.url).toBe('/v1/policies');
    expect(req.headers.authorization).toBe('Bearer jwt-for-org-a');
    expect(req.url).not.toMatch(/org/i);
    expect(JSON.parse(req.body ?? '{}')).not.toHaveProperty('orgId');
    expect(JSON.parse(req.body ?? '{}')).not.toHaveProperty('webhookUrl');
    expect(JSON.parse(req.body ?? '{}').actions).toEqual(['fail_build']);
  });

  it('refuses an org field on a policy create or update body', () => {
    expect(() =>
      buildGatewayRequest('/v1/policies', {
        method: 'POST',
        token: 'jwt',
        body: { name: 'x', actions: ['notify'], orgId: 'other-org' },
      }),
    ).toThrow(/org selector/);
    expect(() =>
      buildGatewayRequest('/v1/policies/11111111-1111-4111-8111-111111111111', {
        method: 'PATCH',
        token: 'jwt',
        body: { priority: 1, organization_id: 'other-org' },
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
    expect(() =>
      buildGatewayRequest('http://localhost:3004/v1/findings', { token: 'jwt' }),
    ).toThrow(/\/v1/);
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

  it('sessionStorage holds the issued JWT and refuses a PAT', () => {
    const storage = memoryStorage();
    const store = tokenStore(storage);
    store.set('eyJhbGciOiJub25lIn0.e30.sig');
    expect(storage.getItem(TOKEN_STORAGE_KEY)).toBe('eyJhbGciOiJub25lIn0.e30.sig');
    expect(isPatToken(storage.getItem(TOKEN_STORAGE_KEY) ?? '')).toBe(false);
    expect(() => store.set('ctem_pat_machine-secret')).toThrow(/PAT/);
    expect(storage.getItem(TOKEN_STORAGE_KEY)).toBe('eyJhbGciOiJub25lIn0.e30.sig');
    expect(storage.getItem(TOKEN_STORAGE_KEY)).not.toMatch(/ctem_pat_/);
  });
});

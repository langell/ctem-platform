import { HttpException, HttpStatus } from '@nestjs/common';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  InternalHttpPolicy,
} from '@ctem/resilience';
import { ServiceProxy } from './service-proxy';

function jsonResponse(status: number, body: unknown = { id: '1' }): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const headers = { principalHeaders: { value: 'p', signature: 's' } };

function policy(
  overrides: Partial<typeof DEFAULT_CIRCUIT_BREAKER_CONFIG> = {},
): InternalHttpPolicy {
  return new InternalHttpPolicy(
    { ...DEFAULT_CIRCUIT_BREAKER_CONFIG, maxAttempts: 3, timeoutMs: 50, ...overrides },
    { sleep: async () => undefined, random: () => 0 },
  );
}

describe('ServiceProxy', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('forwards a successful GET and returns the upstream JSON', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, { items: [] }));
    vi.stubGlobal('fetch', fetchMock);
    const proxy = new ServiceProxy(policy());

    await expect(proxy.forward('asset', 'GET', '/v1/assets', headers)).resolves.toEqual({ items: [] });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('retries a 502 then returns success (retry budget, not a storm)', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(502, { title: 'bad gateway' }))
      .mockResolvedValueOnce(jsonResponse(200, { id: 'ok' }));
    vi.stubGlobal('fetch', fetchMock);
    const proxy = new ServiceProxy(policy({ maxAttempts: 3 }));

    await expect(proxy.forward('findings', 'GET', '/v1/findings', headers)).resolves.toEqual({
      id: 'ok',
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not retry 4xx', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(400, { title: 'bad request' }));
    vi.stubGlobal('fetch', fetchMock);
    const proxy = new ServiceProxy(policy());

    await expect(proxy.forward('identity', 'POST', '/v1/orgs', headers, { body: {} })).rejects.toBeInstanceOf(
      HttpException,
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('maps an open circuit to 503 and never returns an empty/success payload', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(502, { title: 'bad gateway' }));
    vi.stubGlobal('fetch', fetchMock);
    const proxy = new ServiceProxy(policy({ failureThreshold: 1, maxAttempts: 1 }));

    await expect(proxy.forward('orchestrator', 'GET', '/v1/scans', headers)).rejects.toMatchObject({
      status: 502,
    });
    try {
      await proxy.forward('orchestrator', 'GET', '/v1/scans', headers);
      expect.unreachable('open circuit must throw');
    } catch (err) {
      expect(err).toBeInstanceOf(HttpException);
      expect((err as HttpException).getStatus()).toBe(HttpStatus.SERVICE_UNAVAILABLE);
      expect((err as HttpException).getResponse()).toEqual({
        title: 'Upstream unavailable',
        status: 503,
      });
    }
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('maps exhausted timeouts to 504', async () => {
    const timeout = Object.assign(new Error('The operation was aborted due to timeout'), {
      name: 'TimeoutError',
    });
    const fetchMock = vi.fn().mockRejectedValue(timeout);
    vi.stubGlobal('fetch', fetchMock);
    const proxy = new ServiceProxy(policy({ maxAttempts: 2 }));

    try {
      await proxy.forward('risk', 'GET', '/v1/risk', headers);
      expect.unreachable('timeout must throw');
    } catch (err) {
      expect(err).toBeInstanceOf(HttpException);
      expect((err as HttpException).getStatus()).toBe(HttpStatus.GATEWAY_TIMEOUT);
    }
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

import { describe, expect, it, vi } from 'vitest';
import type { NextFunction, Request, Response } from 'express';
import { MemoryRateLimitStore, UnavailableRateLimitStore } from '@ctem/coordination';
import {
  GATEWAY_RATE_LIMIT_CAPACITY,
  RateLimitMiddleware,
} from './rate-limit.middleware';

function mockReq(overrides: Partial<Request> = {}): Request {
  return {
    ip: '203.0.113.50',
    method: 'GET',
    path: '/v1/assets',
    ...overrides,
  } as Request;
}

function mockRes(): Response & { statusCode: number; body: unknown; headers: Record<string, string> } {
  const headers: Record<string, string> = {};
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    headers,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: unknown) {
      this.body = body;
      return this;
    },
    setHeader(name: string, value: string) {
      headers[name.toLowerCase()] = value;
    },
  };
  return res as unknown as Response & {
    statusCode: number;
    body: unknown;
    headers: Record<string, string>;
  };
}

function problem429(res: { statusCode: number; body: unknown }): void {
  expect(res.statusCode).toBe(429);
  expect(res.body).toEqual({
    type: 'about:blank',
    title: 'Rate limit exceeded',
    status: 429,
  });
}

describe('RateLimitMiddleware', () => {
  it('lets two logical gateways share one IP budget', async () => {
    const store = new MemoryRateLimitStore();
    const a = new RateLimitMiddleware(store);
    const b = new RateLimitMiddleware(store);
    const req = mockReq();

    for (let i = 0; i < GATEWAY_RATE_LIMIT_CAPACITY; i += 1) {
      const res = mockRes();
      const next = vi.fn() as unknown as NextFunction;
      await (i % 2 === 0 ? a : b).use(req, res, next);
      expect(next).toHaveBeenCalledOnce();
      expect(res.statusCode).toBe(200);
    }

    const denied = mockRes();
    const next = vi.fn() as unknown as NextFunction;
    await a.use(req, denied, next);
    expect(next).not.toHaveBeenCalled();
    problem429(denied);
  });

  it('returns 429 when Redis is unavailable', async () => {
    const mw = new RateLimitMiddleware(new UnavailableRateLimitStore());
    const res = mockRes();
    const next = vi.fn() as unknown as NextFunction;
    await mw.use(mockReq(), res, next);
    expect(next).not.toHaveBeenCalled();
    problem429(res);
    expect(res.headers['x-ratelimit-remaining']).toBeUndefined();
  });

  it('excludes GET /health, /health/live, and /health/ready from the bucket', async () => {
    const store = new MemoryRateLimitStore();
    const consume = vi.spyOn(store, 'consume');
    const mw = new RateLimitMiddleware(store);

    for (const path of ['/health', '/health/', '/health/live', '/health/ready']) {
      const res = mockRes();
      const next = vi.fn() as unknown as NextFunction;
      await mw.use(mockReq({ path }), res, next);
      expect(next).toHaveBeenCalledOnce();
      expect(res.statusCode).toBe(200);
      expect(res.headers['x-ratelimit-remaining']).toBeUndefined();
    }

    expect(consume).not.toHaveBeenCalled();

    const down = new RateLimitMiddleware(new UnavailableRateLimitStore());
    const live = mockRes();
    const liveNext = vi.fn() as unknown as NextFunction;
    await down.use(mockReq({ path: '/health/live' }), live, liveNext);
    expect(liveNext).toHaveBeenCalledOnce();
    expect(live.statusCode).toBe(200);
  });

  it('sets x-ratelimit-remaining on allow', async () => {
    const mw = new RateLimitMiddleware(new MemoryRateLimitStore());
    const res = mockRes();
    const next = vi.fn() as unknown as NextFunction;
    await mw.use(mockReq(), res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(res.headers['x-ratelimit-remaining']).toBe(String(GATEWAY_RATE_LIMIT_CAPACITY - 1));
  });
});

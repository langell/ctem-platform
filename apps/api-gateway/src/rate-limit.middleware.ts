import { HttpStatus, Inject, Injectable, NestMiddleware, Optional } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import {
  RedisClient,
  UnavailableRateLimitStore,
  gatewayRateLimitRedisKey,
  type RateLimitStore,
} from '@ctem/coordination';
import { rootLogger } from '@ctem/observability';

/** Requests allowed per IP per window. Unchanged from the in-memory limiter. */
export const GATEWAY_RATE_LIMIT_CAPACITY = 600;
/** Window length in ms. Unchanged from the in-memory limiter. */
export const GATEWAY_RATE_LIMIT_WINDOW_MS = 60_000;

/**
 * GET /health, /health/live, and /health/ready must not consume the shared
 * budget or 429 from this limiter — probes have to stay up when Redis is down.
 */
export function isGatewayHealthProbe(req: Pick<Request, 'method' | 'path'>): boolean {
  if (req.method !== 'GET') return false;
  const path = normalizePath(req.path);
  return path === '/health' || path === '/health/live' || path === '/health/ready';
}

function normalizePath(path: string | undefined): string {
  if (!path) return '/';
  const trimmed = path.replace(/\/+$/, '');
  return trimmed.length === 0 ? '/' : trimmed;
}

/**
 * Redis-backed token bucket, keyed by `req.ip` (Express trust-proxy when set).
 * Two api-gateway replicas share one counter per IP. Redis unavailable or a
 * command error fails closed with 429 — same class of dependency as scheduler
 * leader leases. Never keyed by org header, body, query, or JWT.
 */
@Injectable()
export class RateLimitMiddleware implements NestMiddleware {
  private readonly capacity = GATEWAY_RATE_LIMIT_CAPACITY;
  private readonly windowMs = GATEWAY_RATE_LIMIT_WINDOW_MS;
  private readonly store: RateLimitStore;
  private readonly log = rootLogger.child({ component: 'rate-limit' });

  constructor(@Optional() @Inject(RedisClient) store?: RateLimitStore) {
    this.store = store ?? new UnavailableRateLimitStore();
  }

  async use(req: Request, res: Response, next: NextFunction): Promise<void> {
    if (isGatewayHealthProbe(req)) {
      next();
      return;
    }

    const ip = req.ip ?? 'anonymous';
    const key = gatewayRateLimitRedisKey(ip);

    let remaining: number;
    try {
      remaining = await this.store.consume(key, this.capacity, this.windowMs);
    } catch (err) {
      this.log.warn({ err, key }, 'gateway rate limit redis unavailable; failing closed');
      this.reject(res);
      return;
    }

    if (remaining < 0) {
      this.reject(res);
      return;
    }

    res.setHeader('x-ratelimit-remaining', String(remaining));
    next();
  }

  private reject(res: Response): void {
    res.status(HttpStatus.TOO_MANY_REQUESTS).json({
      type: 'about:blank',
      title: 'Rate limit exceeded',
      status: 429,
    });
  }
}

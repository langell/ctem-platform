import { HttpStatus, Injectable, NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';

/**
 * Placeholder token bucket, per org. In-memory only — swap the store for Redis
 * before running more than one gateway replica.
 */
@Injectable()
export class RateLimitMiddleware implements NestMiddleware {
  private readonly buckets = new Map<string, { tokens: number; refilledAt: number }>();
  private readonly capacity = 600; // requests
  private readonly windowMs = 60_000;

  use(req: Request, res: Response, next: NextFunction): void {
    const key = (req.headers['x-ctem-org'] as string) ?? req.ip ?? 'anonymous';
    const now = Date.now();
    const bucket = this.buckets.get(key) ?? { tokens: this.capacity, refilledAt: now };

    const elapsed = now - bucket.refilledAt;
    if (elapsed > this.windowMs) {
      bucket.tokens = this.capacity;
      bucket.refilledAt = now;
    }

    if (bucket.tokens <= 0) {
      res.status(HttpStatus.TOO_MANY_REQUESTS).json({
        type: 'about:blank',
        title: 'Rate limit exceeded',
        status: 429,
      });
      return;
    }

    bucket.tokens -= 1;
    this.buckets.set(key, bucket);
    res.setHeader('x-ratelimit-remaining', String(bucket.tokens));
    next();
  }
}

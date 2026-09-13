/**
 * Shared token-bucket store used by the api-gateway limiter. Production talks
 * to Redis via {@link RedisClient.consume}; tests use {@link MemoryRateLimitStore}
 * so two in-process "replicas" share one counter.
 */
export interface RateLimitStore {
  /**
   * Consume one token for `key`. Returns remaining tokens after the consume
   * (>= 0), or -1 when the bucket is empty.
   * Throws when Redis is unavailable — callers fail closed.
   */
  consume(key: string, capacity: number, windowMs: number): Promise<number>;
}

/** Every operation throws — models a down or unreachable Redis. */
export class UnavailableRateLimitStore implements RateLimitStore {
  async consume(): Promise<number> {
    throw new Error('redis unavailable');
  }
}

interface MemoryBucket {
  tokens: number;
  expiresAt: number;
}

/**
 * In-process Redis stand-in with a fixed-window token bucket. Safe for unit
 * tests, not production — two middleware instances must share one store.
 */
export class MemoryRateLimitStore implements RateLimitStore {
  private readonly keys = new Map<string, MemoryBucket>();

  constructor(private readonly clock: () => number = Date.now) {}

  async consume(key: string, capacity: number, windowMs: number): Promise<number> {
    this.purge(key);
    let bucket = this.keys.get(key);
    if (!bucket) {
      bucket = { tokens: capacity, expiresAt: this.clock() + windowMs };
      this.keys.set(key, bucket);
    }
    if (bucket.tokens <= 0) return -1;
    bucket.tokens -= 1;
    return bucket.tokens;
  }

  private purge(key: string): void {
    const entry = this.keys.get(key);
    if (entry && entry.expiresAt <= this.clock()) this.keys.delete(key);
  }
}

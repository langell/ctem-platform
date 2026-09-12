import { Injectable, OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import type { LeaseStore } from './lease-store';
import type { RateLimitStore } from './rate-limit-store';

const RENEW_LUA = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
else
  return 0
end
`;

const RELEASE_LUA = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
else
  return 0
end
`;

/**
 * Atomic fixed-window token bucket: init remaining=capacity-1 with TTL, else
 * DECR when tokens remain, else -1. Two gateway replicas share one counter.
 */
const CONSUME_LUA = `
local capacity = tonumber(ARGV[1])
local windowMs = tonumber(ARGV[2])
local current = redis.call('GET', KEYS[1])
if not current then
  redis.call('SET', KEYS[1], capacity - 1, 'PX', windowMs)
  return capacity - 1
end
current = tonumber(current)
if current <= 0 then
  return -1
end
return redis.call('DECR', KEYS[1])
`;

/**
 * Shared Redis connection for leader leases and the gateway rate-limit bucket.
 * The process stays up if Redis is down — commands throw. Lease helpers
 * skip-ticks; the gateway limiter fails closed (429) so a replica cannot serve
 * unlimited traffic. Manual kick paths stay ungated.
 */
@Injectable()
export class RedisClient implements LeaseStore, RateLimitStore, OnModuleDestroy {
  private readonly client: Redis;
  private readonly log = rootLogger.child({ component: 'redis' });

  constructor() {
    const env = loadEnv();
    this.client = new Redis(env.REDIS_URL, {
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      connectTimeout: 2_000,
    });
    this.client.on('error', (err) => {
      this.log.warn({ err }, 'redis error');
    });
  }

  async setNxPx(key: string, value: string, ttlMs: number): Promise<boolean> {
    const result = await this.client.set(key, value, 'PX', ttlMs, 'NX');
    return result === 'OK';
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async expireIfValue(key: string, value: string, ttlMs: number): Promise<boolean> {
    const result = await this.client.eval(RENEW_LUA, 1, key, value, String(ttlMs));
    return Number(result) === 1;
  }

  async delIfValue(key: string, value: string): Promise<boolean> {
    const result = await this.client.eval(RELEASE_LUA, 1, key, value);
    return Number(result) === 1;
  }

  async consume(key: string, capacity: number, windowMs: number): Promise<number> {
    const result = await this.client.eval(
      CONSUME_LUA,
      1,
      key,
      String(capacity),
      String(windowMs),
    );
    return Number(result);
  }

  async onModuleDestroy(): Promise<void> {
    try {
      await this.client.quit();
    } catch {
      this.client.disconnect();
    }
  }
}

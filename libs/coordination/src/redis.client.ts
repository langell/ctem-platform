import { Injectable, OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import type { LeaseStore } from './lease-store';

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
 * Shared Redis connection for leader leases. The process stays up if Redis is
 * down — commands fail and the lease helper skip-ticks rather than taking the
 * service (and its manual kick paths) with it.
 */
@Injectable()
export class RedisClient implements LeaseStore, OnModuleDestroy {
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

  async onModuleDestroy(): Promise<void> {
    try {
      await this.client.quit();
    } catch {
      this.client.disconnect();
    }
  }
}

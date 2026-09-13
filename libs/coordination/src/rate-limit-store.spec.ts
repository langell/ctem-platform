import { describe, expect, it } from 'vitest';
import { GATEWAY_RATE_LIMIT_KEY_PREFIX } from './keys';
import {
  MemoryRateLimitStore,
  UnavailableRateLimitStore,
} from './rate-limit-store';

describe('MemoryRateLimitStore', () => {
  it('lets two consumers share one budget for the same key', async () => {
    const store = new MemoryRateLimitStore();
    const key = `${GATEWAY_RATE_LIMIT_KEY_PREFIX}203.0.113.10`;

    expect(await store.consume(key, 3, 60_000)).toBe(2);
    expect(await store.consume(key, 3, 60_000)).toBe(1);
    expect(await store.consume(key, 3, 60_000)).toBe(0);
    expect(await store.consume(key, 3, 60_000)).toBe(-1);
  });

  it('refills after the window elapses', async () => {
    let now = 1_000;
    const store = new MemoryRateLimitStore(() => now);
    const key = `${GATEWAY_RATE_LIMIT_KEY_PREFIX}203.0.113.11`;

    expect(await store.consume(key, 2, 100)).toBe(1);
    expect(await store.consume(key, 2, 100)).toBe(0);
    expect(await store.consume(key, 2, 100)).toBe(-1);

    now += 101;
    expect(await store.consume(key, 2, 100)).toBe(1);
  });

  it('keeps separate keys on separate counters', async () => {
    const store = new MemoryRateLimitStore();
    expect(await store.consume('a', 1, 60_000)).toBe(0);
    expect(await store.consume('b', 1, 60_000)).toBe(0);
    expect(await store.consume('a', 1, 60_000)).toBe(-1);
  });
});

describe('UnavailableRateLimitStore', () => {
  it('throws so callers can fail closed', async () => {
    const store = new UnavailableRateLimitStore();
    await expect(store.consume('any', 600, 60_000)).rejects.toThrow('redis unavailable');
  });
});

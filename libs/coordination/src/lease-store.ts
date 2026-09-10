/**
 * Compare-and-set store used by {@link LeaderLease}. Production talks to Redis;
 * tests use {@link MemoryLeaseStore} so two in-process competitors share one map.
 */
export interface LeaseStore {
  /** SET key value NX PX ttlMs. True when this caller created the key. */
  setNxPx(key: string, value: string, ttlMs: number): Promise<boolean>;
  get(key: string): Promise<string | null>;
  /** PEXPIRE only if the current value matches. */
  expireIfValue(key: string, value: string, ttlMs: number): Promise<boolean>;
  /** DEL only if the current value matches. */
  delIfValue(key: string, value: string): Promise<boolean>;
}

/** Every operation throws — models a down or unreachable Redis. */
export class UnavailableLeaseStore implements LeaseStore {
  async setNxPx(): Promise<boolean> {
    throw new Error('redis unavailable');
  }
  async get(): Promise<string | null> {
    throw new Error('redis unavailable');
  }
  async expireIfValue(): Promise<boolean> {
    throw new Error('redis unavailable');
  }
  async delIfValue(): Promise<boolean> {
    throw new Error('redis unavailable');
  }
}

interface MemoryEntry {
  value: string;
  expiresAt: number;
}

/** In-process Redis stand-in with SET NX + TTL. Safe for unit tests, not production. */
export class MemoryLeaseStore implements LeaseStore {
  private readonly keys = new Map<string, MemoryEntry>();

  constructor(private readonly clock: () => number = Date.now) {}

  async setNxPx(key: string, value: string, ttlMs: number): Promise<boolean> {
    this.purge(key);
    if (this.keys.has(key)) return false;
    this.keys.set(key, { value, expiresAt: this.clock() + ttlMs });
    return true;
  }

  async get(key: string): Promise<string | null> {
    this.purge(key);
    return this.keys.get(key)?.value ?? null;
  }

  async expireIfValue(key: string, value: string, ttlMs: number): Promise<boolean> {
    this.purge(key);
    const entry = this.keys.get(key);
    if (!entry || entry.value !== value) return false;
    entry.expiresAt = this.clock() + ttlMs;
    return true;
  }

  async delIfValue(key: string, value: string): Promise<boolean> {
    this.purge(key);
    const entry = this.keys.get(key);
    if (!entry || entry.value !== value) return false;
    this.keys.delete(key);
    return true;
  }

  /** Drop a key immediately so a follower can acquire without waiting on the clock. */
  expire(key: string): void {
    this.keys.delete(key);
  }

  private purge(key: string): void {
    const entry = this.keys.get(key);
    if (entry && entry.expiresAt <= this.clock()) this.keys.delete(key);
  }
}

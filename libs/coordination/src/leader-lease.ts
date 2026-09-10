import { randomUUID } from 'node:crypto';
import { rootLogger } from '@ctem/observability';
import { DEFAULT_LEASE_TTL_MS } from './keys';
import type { LeaseStore } from './lease-store';

type LogFn = (obj: object, msg: string) => void;

export interface LeaseLogger {
  info: LogFn;
  warn: LogFn;
  child: (bindings: Record<string, unknown>) => LeaseLogger;
}

export interface LeaderLeaseOptions {
  ttlMs?: number;
  holderId?: string;
  logger?: LeaseLogger;
}

/**
 * Redis-style leader lease: SET NX + TTL, renew while holding, release on stop.
 * Fail closed — a store error means this replica is not the leader.
 */
export class LeaderLease {
  readonly key: string;
  readonly holderId: string;
  readonly ttlMs: number;
  private held = false;
  private renewTimer?: NodeJS.Timeout;
  private readonly store: LeaseStore;
  private readonly log: LeaseLogger;

  constructor(store: LeaseStore, key: string, options: LeaderLeaseOptions = {}) {
    this.store = store;
    this.key = key;
    this.ttlMs = options.ttlMs ?? DEFAULT_LEASE_TTL_MS;
    this.holderId = options.holderId ?? `${process.pid}:${randomUUID()}`;
    this.log = (options.logger ?? (rootLogger as unknown as LeaseLogger)).child({
      component: 'leader-lease',
      key,
    });
  }

  isHeld(): boolean {
    return this.held;
  }

  /**
   * Begin background renew / acquire attempts so TTL does not expire between
   * scheduler ticks. Does not throw if Redis is down.
   */
  start(): void {
    if (this.renewTimer) return;
    const interval = Math.max(1_000, Math.floor(this.ttlMs / 3));
    this.renewTimer = setInterval(() => void this.tryHold(), interval);
    void this.tryHold();
  }

  async stop(): Promise<void> {
    if (this.renewTimer) {
      clearInterval(this.renewTimer);
      this.renewTimer = undefined;
    }
    await this.release();
  }

  /**
   * Acquire the lease or renew it if we already hold it.
   * Returns false when another holder exists or the store is unavailable.
   */
  async tryHold(): Promise<boolean> {
    try {
      if (this.held) {
        const renewed = await this.store.expireIfValue(this.key, this.holderId, this.ttlMs);
        if (renewed) return true;
        this.held = false;
      }
      const acquired = await this.store.setNxPx(this.key, this.holderId, this.ttlMs);
      if (acquired) {
        if (!this.held) {
          this.log.info({ holderId: this.holderId, ttlMs: this.ttlMs }, 'acquired leader lease');
        }
        this.held = true;
        return true;
      }
      this.held = false;
      return false;
    } catch (err) {
      this.held = false;
      this.log.warn({ err }, 'leader lease redis unavailable; skipping tick');
      return false;
    }
  }

  async release(): Promise<void> {
    const wasHeld = this.held;
    this.held = false;
    if (!wasHeld) return;
    try {
      await this.store.delIfValue(this.key, this.holderId);
    } catch (err) {
      this.log.warn({ err }, 'leader lease release failed');
    }
  }
}

/** Run `work` only while this replica holds the lease. */
export async function runIfLeader(
  lease: LeaderLease,
  log: Pick<LeaseLogger, 'info'>,
  work: () => Promise<void>,
): Promise<boolean> {
  const held = await lease.tryHold();
  if (!held) {
    log.info({ key: lease.key }, 'skipping scheduled tick (no leader lease)');
    return false;
  }
  await work();
  return true;
}

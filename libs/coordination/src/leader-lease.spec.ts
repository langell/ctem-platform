import { describe, expect, it } from 'vitest';
import {
  DISCOVERY_SCHEDULE_LEASE_KEY,
  SCAN_SCHEDULE_LEASE_KEY,
} from './keys';
import { LeaderLease } from './leader-lease';
import { MemoryLeaseStore, UnavailableLeaseStore } from './lease-store';

describe('LeaderLease', () => {
  it('lets only one of two competitors hold the same key', async () => {
    const store = new MemoryLeaseStore();
    const a = new LeaderLease(store, SCAN_SCHEDULE_LEASE_KEY, { holderId: 'a', ttlMs: 1_000 });
    const b = new LeaderLease(store, SCAN_SCHEDULE_LEASE_KEY, { holderId: 'b', ttlMs: 1_000 });

    expect(await a.tryHold()).toBe(true);
    expect(await b.tryHold()).toBe(false);
    expect(a.isHeld()).toBe(true);
    expect(b.isHeld()).toBe(false);

    const ticks = { a: 0, b: 0 };
    if (await a.tryHold()) ticks.a += 1;
    if (await b.tryHold()) ticks.b += 1;
    expect(ticks).toEqual({ a: 1, b: 0 });
  });

  it('fails over after TTL expiry without a renew', async () => {
    let now = 1_000;
    const store = new MemoryLeaseStore(() => now);
    const a = new LeaderLease(store, SCAN_SCHEDULE_LEASE_KEY, { holderId: 'a', ttlMs: 100 });
    const b = new LeaderLease(store, SCAN_SCHEDULE_LEASE_KEY, { holderId: 'b', ttlMs: 100 });

    expect(await a.tryHold()).toBe(true);
    expect(await b.tryHold()).toBe(false);

    now += 101;
    expect(await b.tryHold()).toBe(true);
    expect(await a.tryHold()).toBe(false);
  });

  it('renew extends TTL so a follower cannot steal the lease', async () => {
    let now = 1_000;
    const store = new MemoryLeaseStore(() => now);
    const a = new LeaderLease(store, DISCOVERY_SCHEDULE_LEASE_KEY, { holderId: 'a', ttlMs: 100 });
    const b = new LeaderLease(store, DISCOVERY_SCHEDULE_LEASE_KEY, { holderId: 'b', ttlMs: 100 });

    expect(await a.tryHold()).toBe(true);
    now += 90;
    expect(await a.tryHold()).toBe(true);
    now += 90;
    expect(await b.tryHold()).toBe(false);
  });

  it('releases on stop so the other replica can acquire', async () => {
    const store = new MemoryLeaseStore();
    const a = new LeaderLease(store, SCAN_SCHEDULE_LEASE_KEY, { holderId: 'a', ttlMs: 5_000 });
    const b = new LeaderLease(store, SCAN_SCHEDULE_LEASE_KEY, { holderId: 'b', ttlMs: 5_000 });

    expect(await a.tryHold()).toBe(true);
    await a.stop();
    expect(await b.tryHold()).toBe(true);
  });

  it('uses distinct keys so scan and discovery leaders do not contend', async () => {
    const store = new MemoryLeaseStore();
    const scan = new LeaderLease(store, SCAN_SCHEDULE_LEASE_KEY, { holderId: 'scan', ttlMs: 1_000 });
    const discovery = new LeaderLease(store, DISCOVERY_SCHEDULE_LEASE_KEY, {
      holderId: 'discovery',
      ttlMs: 1_000,
    });

    expect(await scan.tryHold()).toBe(true);
    expect(await discovery.tryHold()).toBe(true);
  });

  it('fails closed when Redis is down — neither competitor holds', async () => {
    const store = new UnavailableLeaseStore();
    const a = new LeaderLease(store, SCAN_SCHEDULE_LEASE_KEY, { holderId: 'a' });
    const b = new LeaderLease(store, SCAN_SCHEDULE_LEASE_KEY, { holderId: 'b' });

    expect(await a.tryHold()).toBe(false);
    expect(await b.tryHold()).toBe(false);
    expect(a.isHeld()).toBe(false);
    expect(b.isHeld()).toBe(false);
  });
});

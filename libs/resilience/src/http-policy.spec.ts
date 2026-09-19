import { describe, expect, it, vi } from 'vitest';
import { CircuitBreakerConfigError, CircuitOpenError } from './errors';
import { DEFAULT_CIRCUIT_BREAKER_CONFIG } from './config';
import { InternalHttpPolicy } from './http-policy';
import { isRetryableHttpStatus, retryDelayMs } from './retry';

function ok(status = 200): Response {
  return new Response(JSON.stringify({ ok: true }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function policy(
  overrides: Partial<ConstructorParameters<typeof InternalHttpPolicy>[0]> = {},
  deps: ConstructorParameters<typeof InternalHttpPolicy>[1] = {},
): InternalHttpPolicy {
  return new InternalHttpPolicy(
    {
      ...DEFAULT_CIRCUIT_BREAKER_CONFIG,
      failureThreshold: 2,
      windowMs: 10_000,
      cooldownMs: 1_000,
      maxAttempts: 3,
      baseDelayMs: 10,
      timeoutMs: 50,
      ...overrides,
    },
    { sleep: async () => undefined, random: () => 0, ...deps },
  );
}

describe('InternalHttpPolicy', () => {
  it('retries timeouts and 502–504 up to the budget, then returns the last response', async () => {
    const p = policy({ maxAttempts: 3 });
    const attempt = vi
      .fn<(signal: AbortSignal) => Promise<Response>>()
      .mockResolvedValueOnce(ok(502))
      .mockResolvedValueOnce(ok(503))
      .mockResolvedValueOnce(ok(504));

    const res = await p.execute('asset', attempt);
    expect(res.status).toBe(504);
    expect(attempt).toHaveBeenCalledTimes(3);
  });

  it('does not retry 4xx (including 408 / 429) and does not trip the circuit', async () => {
    const p = policy({ failureThreshold: 1, maxAttempts: 3 });
    for (const status of [400, 401, 403, 404, 408, 429]) {
      const attempt = vi.fn().mockResolvedValue(ok(status));
      const res = await p.execute('findings', attempt);
      expect(res.status).toBe(status);
      expect(attempt).toHaveBeenCalledTimes(1);
    }
    const success = vi.fn().mockResolvedValue(ok(200));
    await expect(p.execute('findings', success)).resolves.toMatchObject({ status: 200 });
    expect(success).toHaveBeenCalledTimes(1);
  });

  it('does not retry 500 but records it as a circuit failure', async () => {
    const p = policy({ failureThreshold: 1, maxAttempts: 4 });
    const attempt = vi.fn().mockResolvedValue(ok(500));
    const res = await p.execute('risk', attempt);
    expect(res.status).toBe(500);
    expect(attempt).toHaveBeenCalledTimes(1);
    await expect(p.execute('risk', vi.fn())).rejects.toBeInstanceOf(CircuitOpenError);
  });

  it('stops retrying after a success within the budget', async () => {
    const p = policy({ maxAttempts: 3 });
    const attempt = vi.fn().mockResolvedValueOnce(ok(502)).mockResolvedValueOnce(ok(200));
    const res = await p.execute('orchestrator', attempt);
    expect(res.status).toBe(200);
    expect(attempt).toHaveBeenCalledTimes(2);
  });

  it('caps the retry budget — no retry storm on a stuck 502', async () => {
    const p = policy({ maxAttempts: 2 });
    const attempt = vi.fn().mockResolvedValue(ok(502));
    await p.execute('reporting', attempt);
    expect(attempt).toHaveBeenCalledTimes(2);
    await p.execute('reporting', attempt);
    expect(attempt).toHaveBeenCalledTimes(4);
  });

  it('opens after the threshold and fail-fasts later calls (no attempt, no success payload)', async () => {
    const p = policy({ failureThreshold: 2, maxAttempts: 1 });
    await p.execute('notification', () => Promise.resolve(ok(502)));
    await p.execute('notification', () => Promise.resolve(ok(502)));

    const attempt = vi.fn().mockResolvedValue(ok(200));
    await expect(p.execute('notification', attempt)).rejects.toBeInstanceOf(CircuitOpenError);
    expect(attempt).not.toHaveBeenCalled();
  });

  it('half-open probe success closes; later calls run again', async () => {
    let t = 0;
    const p = policy({ failureThreshold: 1, maxAttempts: 1, cooldownMs: 100 }, { now: () => t });
    await p.execute('identity', () => Promise.resolve(ok(502)));
    t += 100;
    const probe = vi.fn().mockResolvedValue(ok(200));
    await expect(p.execute('identity', probe)).resolves.toMatchObject({ status: 200 });
    expect(probe).toHaveBeenCalledTimes(1);
    const next = vi.fn().mockResolvedValue(ok(200));
    await expect(p.execute('identity', next)).resolves.toMatchObject({ status: 200 });
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('half-open uses a single attempt (no retry storm on the probe)', async () => {
    let t = 0;
    const p = policy({ failureThreshold: 1, maxAttempts: 5, cooldownMs: 50 }, { now: () => t });
    await p.execute('asset', () => Promise.resolve(ok(502)));
    t += 50;
    const probe = vi.fn().mockResolvedValue(ok(502));
    const res = await p.execute('asset', probe);
    expect(res.status).toBe(502);
    expect(probe).toHaveBeenCalledTimes(1);
    await expect(p.execute('asset', vi.fn())).rejects.toBeInstanceOf(CircuitOpenError);
  });

  it('rejects concurrent half-open callers so only one probe runs', async () => {
    let t = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const p = policy({ failureThreshold: 1, maxAttempts: 1, cooldownMs: 10 }, { now: () => t });
    await p.execute('identity', () => Promise.resolve(ok(503)));
    t += 10;

    const probe = vi.fn(async () => {
      await gate;
      return ok(200);
    });
    const first = p.execute('identity', probe);
    await expect(p.execute('identity', vi.fn())).rejects.toBeInstanceOf(CircuitOpenError);
    release();
    await expect(first).resolves.toMatchObject({ status: 200 });
    expect(probe).toHaveBeenCalledTimes(1);
  });

  it('retries a timeout then succeeds', async () => {
    const p = policy({ maxAttempts: 2, timeoutMs: 20 });
    const timeout = Object.assign(new Error('The operation was aborted due to timeout'), {
      name: 'TimeoutError',
    });
    const attempt = vi.fn().mockRejectedValueOnce(timeout).mockResolvedValueOnce(ok(200));
    await expect(p.execute('asset', attempt)).resolves.toMatchObject({ status: 200 });
    expect(attempt).toHaveBeenCalledTimes(2);
  });

  it('isolates circuits per upstream name', async () => {
    const p = policy({ failureThreshold: 1, maxAttempts: 1 });
    await p.execute('identity', () => Promise.resolve(ok(502)));
    await expect(p.execute('identity', vi.fn())).rejects.toBeInstanceOf(CircuitOpenError);
    const asset = vi.fn().mockResolvedValue(ok(200));
    await expect(p.execute('asset', asset)).resolves.toMatchObject({ status: 200 });
    expect(asset).toHaveBeenCalledTimes(1);
  });

  it('fromEnv fails closed on invalid CTEM_CB_* and never builds a policy that would succeed', () => {
    expect(() => InternalHttpPolicy.fromEnv(undefined, { CTEM_CB_FAILURE_THRESHOLD: 'nope' })).toThrow(
      CircuitBreakerConfigError,
    );
    expect(() => InternalHttpPolicy.fromEnv(undefined, { CTEM_CB_ENABLED: 'false' })).toThrow(/fail closed/);
  });
});

describe('retryDelayMs', () => {
  it('uses exponential cap with full jitter (never above the cap)', () => {
    expect(retryDelayMs(1, 100, () => 0)).toBe(0);
    expect(retryDelayMs(1, 100, () => 0.999)).toBe(100);
    expect(retryDelayMs(2, 100, () => 0.999)).toBe(200);
    expect(retryDelayMs(3, 100, () => 0.999)).toBe(400);
  });
});

describe('isRetryableHttpStatus', () => {
  it('is only 502–504', () => {
    expect([408, 429, 500, 501, 502, 503, 504, 200].filter(isRetryableHttpStatus)).toEqual([
      502, 503, 504,
    ]);
  });
});

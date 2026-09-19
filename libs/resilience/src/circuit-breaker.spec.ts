import { describe, expect, it, vi } from 'vitest';
import { CircuitBreaker } from './circuit-breaker';
import { CircuitOpenError } from './errors';

function breaker(now: () => number, log?: { info: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn> }) {
  return new CircuitBreaker(
    'identity',
    { failureThreshold: 3, windowMs: 1_000, cooldownMs: 500 },
    { now, log },
  );
}

describe('CircuitBreaker', () => {
  it('opens after the failure threshold in the window', () => {
    let t = 1_000;
    const cb = breaker(() => t);
    cb.recordFailure();
    cb.recordFailure();
    expect(cb.state).toBe('closed');
    cb.recordFailure();
    expect(cb.state).toBe('open');
  });

  it('does not count failures that have aged out of the window', () => {
    let t = 1_000;
    const cb = breaker(() => t);
    cb.recordFailure();
    cb.recordFailure();
    t += 1_001;
    cb.recordFailure();
    expect(cb.state).toBe('closed');
    cb.recordFailure();
    expect(cb.state).toBe('closed');
    cb.recordFailure();
    expect(cb.state).toBe('open');
  });

  it('fail-fast while open — enter throws and does not admit a probe', () => {
    let t = 1_000;
    const cb = breaker(() => t);
    cb.recordFailure();
    cb.recordFailure();
    cb.recordFailure();
    expect(() => cb.enter()).toThrow(CircuitOpenError);
    expect(() => cb.enter()).toThrow(/identity/);
  });

  it('half-open success closes so later calls are admitted', () => {
    let t = 1_000;
    const cb = breaker(() => t);
    cb.recordFailure();
    cb.recordFailure();
    cb.recordFailure();
    t += 500;
    expect(cb.state).toBe('half_open');
    cb.enter();
    cb.recordSuccess();
    cb.leave();
    expect(cb.state).toBe('closed');
    expect(() => cb.enter()).not.toThrow();
    cb.leave();
  });

  it('half-open failure re-opens', () => {
    let t = 1_000;
    const cb = breaker(() => t);
    cb.recordFailure();
    cb.recordFailure();
    cb.recordFailure();
    t += 500;
    cb.enter();
    cb.recordFailure();
    cb.leave();
    expect(cb.state).toBe('open');
    expect(() => cb.enter()).toThrow(CircuitOpenError);
  });

  it('rejects concurrent callers while a half-open probe is in flight', () => {
    let t = 1_000;
    const cb = breaker(() => t);
    cb.recordFailure();
    cb.recordFailure();
    cb.recordFailure();
    t += 500;
    cb.enter();
    expect(() => cb.enter()).toThrow(CircuitOpenError);
    cb.recordSuccess();
    cb.leave();
    expect(cb.state).toBe('closed');
  });

  it('emits structured logs on open / half-open / reject without request fields', () => {
    let t = 1_000;
    const log = { info: vi.fn(), warn: vi.fn() };
    const cb = breaker(() => t, log);
    cb.recordFailure();
    cb.recordFailure();
    cb.recordFailure();
    expect(log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ circuit: 'identity', state: 'open' }),
      'circuit opened',
    );
    expect(() => cb.enter()).toThrow(CircuitOpenError);
    expect(log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ circuit: 'identity', state: 'reject' }),
      'circuit reject',
    );
    t += 500;
    expect(cb.state).toBe('half_open');
    expect(log.info).toHaveBeenCalledWith(
      expect.objectContaining({ circuit: 'identity', state: 'half_open' }),
      'circuit half-open',
    );
    const payloads = [...log.warn.mock.calls, ...log.info.mock.calls].map(([obj]) => obj);
    for (const obj of payloads) {
      expect(obj).not.toHaveProperty('authorization');
      expect(obj).not.toHaveProperty('token');
      expect(obj).not.toHaveProperty('principal');
    }
  });
});

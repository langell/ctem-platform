import { describe, expect, it } from 'vitest';
import {
  CTEM_CB_ENV_ALLOWLIST,
  CTEM_CB_KNOWN_KEYS,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  loadCircuitBreakerConfig,
} from './config';
import { CircuitBreakerConfigError } from './errors';

describe('loadCircuitBreakerConfig', () => {
  it('uses conservative defaults when no CTEM_CB_* keys are set', () => {
    expect(loadCircuitBreakerConfig({})).toEqual(DEFAULT_CIRCUIT_BREAKER_CONFIG);
  });

  it('reads only allowlisted CTEM_CB_* integers', () => {
    expect(
      loadCircuitBreakerConfig({
        CTEM_CB_FAILURE_THRESHOLD: '3',
        CTEM_CB_WINDOW_MS: '1000',
        CTEM_CB_COOLDOWN_MS: '2000',
        CTEM_CB_MAX_ATTEMPTS: '2',
        CTEM_CB_BASE_DELAY_MS: '25',
        CTEM_CB_TIMEOUT_MS: '500',
        UNRELATED: 'nope',
        DATABASE_URL: 'postgresql://x',
      }),
    ).toEqual({
      failureThreshold: 3,
      windowMs: 1000,
      cooldownMs: 2000,
      maxAttempts: 2,
      baseDelayMs: 25,
      timeoutMs: 500,
    });
  });

  it('fails closed on non-integer values', () => {
    expect(() => loadCircuitBreakerConfig({ CTEM_CB_FAILURE_THRESHOLD: 'abc' })).toThrow(
      CircuitBreakerConfigError,
    );
    expect(() => loadCircuitBreakerConfig({ CTEM_CB_MAX_ATTEMPTS: '3.5' })).toThrow(/fail closed/);
    expect(() => loadCircuitBreakerConfig({ CTEM_CB_WINDOW_MS: '' })).toThrow(/fail closed/);
    expect(() => loadCircuitBreakerConfig({ CTEM_CB_TIMEOUT_MS: '-1' })).toThrow(/fail closed/);
  });

  it('fails closed on out-of-range values (including zero)', () => {
    expect(() => loadCircuitBreakerConfig({ CTEM_CB_FAILURE_THRESHOLD: '0' })).toThrow(/fail closed/);
    expect(() => loadCircuitBreakerConfig({ CTEM_CB_MAX_ATTEMPTS: '0' })).toThrow(/fail closed/);
    expect(() => loadCircuitBreakerConfig({ CTEM_CB_MAX_ATTEMPTS: '99' })).toThrow(/fail closed/);
    expect(() => loadCircuitBreakerConfig({ CTEM_CB_WINDOW_MS: '1' })).toThrow(/fail closed/);
  });

  it('fails closed on unknown CTEM_CB_* keys (allowlist only)', () => {
    expect(() => loadCircuitBreakerConfig({ CTEM_CB_ENABLED: 'true' })).toThrow(CircuitBreakerConfigError);
    expect(() => loadCircuitBreakerConfig({ CTEM_CB_ENABLED: 'true' })).toThrow(/allowlisted/);
    expect(() => loadCircuitBreakerConfig({ CTEM_CB_NOT_A_KNOB: '1' })).toThrow(/fail closed/);
    expect(CTEM_CB_ENV_ALLOWLIST.test('CTEM_CB_ENABLED')).toBe(true);
    expect(CTEM_CB_KNOWN_KEYS).not.toContain('CTEM_CB_ENABLED');
  });

  it('ignores env names that are not CTEM_CB_*', () => {
    expect(loadCircuitBreakerConfig({ CTEM_PUBLIC_URL: 'https://x', FOO: '1' })).toEqual(
      DEFAULT_CIRCUIT_BREAKER_CONFIG,
    );
  });
});

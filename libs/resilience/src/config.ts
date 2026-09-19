import { CircuitBreakerConfigError } from './errors';

/**
 * Platform-operated knobs for the inter-service breaker + retry budget.
 * Only these names are accepted; any other `CTEM_CB_*` key fails closed.
 * Not tenant-writable — there is no credentialRef / body / query path.
 */
export const CTEM_CB_ENV_ALLOWLIST = /^CTEM_CB_[A-Z0-9_]+$/;

export const CTEM_CB_KNOWN_KEYS = [
  'CTEM_CB_FAILURE_THRESHOLD',
  'CTEM_CB_WINDOW_MS',
  'CTEM_CB_COOLDOWN_MS',
  'CTEM_CB_MAX_ATTEMPTS',
  'CTEM_CB_BASE_DELAY_MS',
  'CTEM_CB_TIMEOUT_MS',
] as const;

export type CtemCbEnvKey = (typeof CTEM_CB_KNOWN_KEYS)[number];

export interface CircuitBreakerConfig {
  /** Failures in `windowMs` that trip the circuit from closed → open. */
  failureThreshold: number;
  /** Sliding window (ms) that failure timestamps are counted in. */
  windowMs: number;
  /** After opening, wait this long before a single half-open probe. */
  cooldownMs: number;
  /** Total tries per call (1 = no retry). Closed-state only; half-open is 1. */
  maxAttempts: number;
  /** Exponential backoff base; delay is `random(0, base * 2^(attempt-1))`. */
  baseDelayMs: number;
  /** Per-attempt AbortSignal timeout. */
  timeoutMs: number;
}

/**
 * Conservative defaults. Documented in `.env.example` and architecture.md.
 * Threshold 5 / 30s window / 15s cooldown / 3 attempts / 100ms base / 30s timeout.
 */
export const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  windowMs: 30_000,
  cooldownMs: 15_000,
  maxAttempts: 3,
  baseDelayMs: 100,
  timeoutMs: 30_000,
};

const BOUNDS: Record<
  keyof CircuitBreakerConfig,
  { key: CtemCbEnvKey; min: number; max: number }
> = {
  failureThreshold: { key: 'CTEM_CB_FAILURE_THRESHOLD', min: 1, max: 100 },
  windowMs: { key: 'CTEM_CB_WINDOW_MS', min: 100, max: 600_000 },
  cooldownMs: { key: 'CTEM_CB_COOLDOWN_MS', min: 100, max: 600_000 },
  maxAttempts: { key: 'CTEM_CB_MAX_ATTEMPTS', min: 1, max: 8 },
  baseDelayMs: { key: 'CTEM_CB_BASE_DELAY_MS', min: 1, max: 10_000 },
  timeoutMs: { key: 'CTEM_CB_TIMEOUT_MS', min: 100, max: 120_000 },
};

/**
 * Read allowlisted `CTEM_CB_*` from `source` (default `process.env`).
 * Unknown `CTEM_CB_*` names or non-integer / out-of-range values throw
 * {@link CircuitBreakerConfigError} — fail closed, no silent defaults.
 */
export function loadCircuitBreakerConfig(
  source: NodeJS.ProcessEnv = process.env,
): CircuitBreakerConfig {
  for (const key of Object.keys(source)) {
    if (!CTEM_CB_ENV_ALLOWLIST.test(key)) continue;
    if (!(CTEM_CB_KNOWN_KEYS as readonly string[]).includes(key)) {
      throw new CircuitBreakerConfigError(
        `Unknown circuit-breaker env ${key}; only ${CTEM_CB_KNOWN_KEYS.join(', ')} are allowlisted (fail closed)`,
      );
    }
  }

  return {
    failureThreshold: readInt(source, BOUNDS.failureThreshold, DEFAULT_CIRCUIT_BREAKER_CONFIG.failureThreshold),
    windowMs: readInt(source, BOUNDS.windowMs, DEFAULT_CIRCUIT_BREAKER_CONFIG.windowMs),
    cooldownMs: readInt(source, BOUNDS.cooldownMs, DEFAULT_CIRCUIT_BREAKER_CONFIG.cooldownMs),
    maxAttempts: readInt(source, BOUNDS.maxAttempts, DEFAULT_CIRCUIT_BREAKER_CONFIG.maxAttempts),
    baseDelayMs: readInt(source, BOUNDS.baseDelayMs, DEFAULT_CIRCUIT_BREAKER_CONFIG.baseDelayMs),
    timeoutMs: readInt(source, BOUNDS.timeoutMs, DEFAULT_CIRCUIT_BREAKER_CONFIG.timeoutMs),
  };
}

function readInt(
  source: NodeJS.ProcessEnv,
  bound: { key: CtemCbEnvKey; min: number; max: number },
  fallback: number,
): number {
  const raw = source[bound.key];
  if (raw === undefined) return fallback;
  const trimmed = raw.trim();
  if (!/^[0-9]+$/.test(trimmed)) {
    throw new CircuitBreakerConfigError(
      `Invalid ${bound.key}; expected integer ${bound.min}..${bound.max} (fail closed)`,
    );
  }
  const n = Number(trimmed);
  if (!Number.isSafeInteger(n) || n < bound.min || n > bound.max) {
    throw new CircuitBreakerConfigError(
      `Invalid ${bound.key}; expected integer ${bound.min}..${bound.max} (fail closed)`,
    );
  }
  return n;
}

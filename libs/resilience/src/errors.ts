/** Thrown when a circuit is open (or a half-open probe is already in flight). */
export class CircuitOpenError extends Error {
  readonly code = 'CIRCUIT_OPEN' as const;

  constructor(readonly circuit: string) {
    super(`circuit open: ${circuit}`);
    this.name = 'CircuitOpenError';
  }
}

/** Thrown when a CTEM_CB_* env value is missing-invalid, out of range, or unknown. */
export class CircuitBreakerConfigError extends Error {
  readonly code = 'CIRCUIT_BREAKER_CONFIG' as const;

  constructor(message: string) {
    super(message);
    this.name = 'CircuitBreakerConfigError';
  }
}

export function isCircuitOpenError(err: unknown): err is CircuitOpenError {
  return err instanceof CircuitOpenError;
}

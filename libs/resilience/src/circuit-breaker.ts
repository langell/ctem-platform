import type { CircuitBreakerConfig } from './config';
import { CircuitOpenError } from './errors';

export type CircuitState = 'closed' | 'open' | 'half_open';

export interface ResilienceLog {
  info(bindings: Record<string, unknown>, msg: string): void;
  warn(bindings: Record<string, unknown>, msg: string): void;
}

export interface CircuitBreakerDeps {
  now?: () => number;
  log?: ResilienceLog;
}

/**
 * In-process circuit: closed → open after `failureThreshold` failures in
 * `windowMs`; fail-fast while open; half-open after `cooldownMs`; a successful
 * probe closes. One in-flight half-open probe — concurrent callers reject.
 *
 * Open never returns a success/empty payload; callers must throw / map to 503.
 */
export class CircuitBreaker {
  private current: CircuitState = 'closed';
  private failures: number[] = [];
  private openedAt = 0;
  private probeInFlight = false;
  private readonly now: () => number;
  private readonly log?: ResilienceLog;

  constructor(
    readonly name: string,
    private readonly config: Pick<CircuitBreakerConfig, 'failureThreshold' | 'windowMs' | 'cooldownMs'>,
    deps: CircuitBreakerDeps = {},
  ) {
    this.now = deps.now ?? Date.now;
    this.log = deps.log;
  }

  get state(): CircuitState {
    this.transitionIfCooldownElapsed();
    return this.current;
  }

  /** Admit a call or throw {@link CircuitOpenError}. */
  enter(): void {
    this.transitionIfCooldownElapsed();
    if (this.current === 'open') {
      this.emit('warn', 'reject', 'circuit reject');
      throw new CircuitOpenError(this.name);
    }
    if (this.current === 'half_open') {
      if (this.probeInFlight) {
        this.emit('warn', 'reject', 'circuit reject');
        throw new CircuitOpenError(this.name);
      }
      this.probeInFlight = true;
    }
  }

  /** Clear the half-open in-flight flag. Safe if the call never took a probe. */
  leave(): void {
    this.probeInFlight = false;
  }

  recordSuccess(): void {
    if (this.current === 'half_open' || this.current === 'open') {
      this.current = 'closed';
      this.failures = [];
      this.emit('info', 'closed', 'circuit closed');
      return;
    }
    this.prune();
  }

  recordFailure(): void {
    const now = this.now();
    if (this.current === 'half_open') {
      this.open(now);
      return;
    }
    this.prune();
    this.failures.push(now);
    if (this.failures.length >= this.config.failureThreshold) {
      this.open(now);
    }
  }

  private transitionIfCooldownElapsed(): void {
    if (this.current === 'open' && this.now() - this.openedAt >= this.config.cooldownMs) {
      this.current = 'half_open';
      this.emit('info', 'half_open', 'circuit half-open');
    }
  }

  private open(now: number): void {
    const wasOpen = this.current === 'open';
    this.current = 'open';
    this.openedAt = now;
    this.failures = [];
    if (!wasOpen) this.emit('warn', 'open', 'circuit opened');
  }

  private prune(): void {
    const cutoff = this.now() - this.config.windowMs;
    if (this.failures.length === 0) return;
    this.failures = this.failures.filter((ts) => ts > cutoff);
  }

  private emit(level: 'info' | 'warn', state: CircuitState | 'reject', msg: string): void {
    const bindings = {
      circuit: this.name,
      state,
      threshold: this.config.failureThreshold,
      windowMs: this.config.windowMs,
      cooldownMs: this.config.cooldownMs,
    };
    if (level === 'warn') this.log?.warn(bindings, msg);
    else this.log?.info(bindings, msg);
  }
}

export class CircuitBreakerRegistry {
  private readonly circuits = new Map<string, CircuitBreaker>();

  constructor(
    private readonly config: Pick<CircuitBreakerConfig, 'failureThreshold' | 'windowMs' | 'cooldownMs'>,
    private readonly deps: CircuitBreakerDeps = {},
  ) {}

  for(name: string): CircuitBreaker {
    let circuit = this.circuits.get(name);
    if (!circuit) {
      circuit = new CircuitBreaker(name, this.config, this.deps);
      this.circuits.set(name, circuit);
    }
    return circuit;
  }
}

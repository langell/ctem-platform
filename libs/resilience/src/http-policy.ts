import { CircuitBreakerRegistry, type ResilienceLog } from './circuit-breaker';
import {
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  loadCircuitBreakerConfig,
  type CircuitBreakerConfig,
} from './config';
import { isRetryableError, isRetryableHttpStatus, retryDelayMs } from './retry';

export interface InternalHttpPolicyDeps {
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
  log?: ResilienceLog;
}

/**
 * Shared HTTP circuit + retry budget. One policy type for api-gateway
 * `ServiceProxy` (internal service-to-service) and orchestrator publisher
 * egress (GitHub / GitLab, separate circuit names). Not a second breaker.
 *
 * Retry budget: at most `maxAttempts` tries (default 3) with exponential
 * backoff + full jitter. Retries **timeouts** and **502 / 503 / 504** only.
 * No retry on 4xx (408 / 429 included — this path did not treat them as
 * retryable before). 5xx other than 502–504 is not retried but still trips
 * the circuit. 2xx / 3xx / 4xx count as a reachable upstream (circuit success).
 *
 * Circuit: per-name breaker. Threshold failures in the window → open →
 * subsequent calls throw {@link CircuitOpenError} (fail fast; no empty /
 * success payload). After cooldown, one half-open probe (single attempt, no
 * retry storm); success closes, failure re-opens.
 */
export class InternalHttpPolicy {
  private readonly registry: CircuitBreakerRegistry;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly random: () => number;

  constructor(
    private readonly config: CircuitBreakerConfig = DEFAULT_CIRCUIT_BREAKER_CONFIG,
    deps: InternalHttpPolicyDeps = {},
  ) {
    this.registry = new CircuitBreakerRegistry(config, { now: deps.now, log: deps.log });
    this.sleep = deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.random = deps.random ?? Math.random;
  }

  /** Load allowlisted `CTEM_CB_*` (fail closed on invalid) and build a policy. */
  static fromEnv(log?: ResilienceLog, source: NodeJS.ProcessEnv = process.env): InternalHttpPolicy {
    return new InternalHttpPolicy(loadCircuitBreakerConfig(source), { log });
  }

  async execute(name: string, attempt: (signal: AbortSignal) => Promise<Response>): Promise<Response> {
    const circuit = this.registry.for(name);
    circuit.enter();

    const budget = circuit.state === 'half_open' ? 1 : this.config.maxAttempts;
    let lastError: unknown;

    try {
      for (let i = 1; i <= budget; i += 1) {
        const signal = AbortSignal.timeout(this.config.timeoutMs);
        try {
          const res = await attempt(signal);
          if (res.ok || !isRetryableHttpStatus(res.status)) {
            this.recordHttpOutcome(circuit, res.status);
            return res;
          }
          if (i === budget) {
            circuit.recordFailure();
            return res;
          }
        } catch (err) {
          lastError = err;
          if (!isRetryableError(err) || i === budget) {
            circuit.recordFailure();
            throw err;
          }
        }
        const delay = retryDelayMs(i, this.config.baseDelayMs, this.random);
        if (delay > 0) await this.sleep(delay);
      }

      circuit.recordFailure();
      throw lastError ?? new Error(`retry budget exhausted: ${name}`);
    } finally {
      circuit.leave();
    }
  }

  private recordHttpOutcome(
    circuit: { recordSuccess: () => void; recordFailure: () => void },
    status: number,
  ): void {
    if (status >= 500) {
      circuit.recordFailure();
      return;
    }
    circuit.recordSuccess();
  }
}

import { HttpException, HttpStatus, Injectable, Optional } from '@nestjs/common';
import { PRINCIPAL_HEADER, PRINCIPAL_SIGNATURE_HEADER } from '@ctem/auth';
import { loadEnv } from '@ctem/config';
import { currentTraceId, rootLogger } from '@ctem/observability';
import {
  CircuitOpenError,
  InternalHttpPolicy,
  isTimeoutError,
  isRetryableError,
} from '@ctem/resilience';

export type UpstreamService =
  | 'identity'
  | 'asset'
  | 'orchestrator'
  | 'findings'
  | 'risk'
  | 'reporting'
  | 'notification';

/**
 * REST forwarding with the signed principal attached. Deliberately not a
 * transparent HTTP proxy: every forwarded route is declared in a controller so
 * the public API surface stays reviewable.
 *
 * Outbound calls go through {@link InternalHttpPolicy} (`@ctem/resilience`):
 * per-upstream circuit + capped retry on timeouts / 502–504. An open circuit
 * maps to HTTP 503 (fail fast — never an empty or success payload). This is
 * the only path this slice wraps; gateway-auth identity verify and third-party
 * egress are unchanged.
 */
@Injectable()
export class ServiceProxy {
  private readonly log = rootLogger.child({ component: 'proxy' });
  private readonly policy: InternalHttpPolicy;

  constructor(@Optional() policy?: InternalHttpPolicy) {
    this.policy = policy ?? InternalHttpPolicy.fromEnv(this.log);
  }

  private baseUrl(service: UpstreamService): string {
    const env = loadEnv();
    const map: Record<UpstreamService, string> = {
      identity: env.IDENTITY_SERVICE_URL,
      asset: env.ASSET_SERVICE_URL,
      orchestrator: env.ORCHESTRATOR_SERVICE_URL,
      findings: env.FINDINGS_SERVICE_URL,
      risk: env.RISK_SERVICE_URL,
      reporting: env.REPORTING_SERVICE_URL,
      notification: env.NOTIFICATION_SERVICE_URL,
    };
    return map[service];
  }

  async forward<T>(
    service: UpstreamService,
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    path: string,
    req: { principalHeaders: { value: string; signature: string } },
    init: { body?: unknown; query?: Record<string, unknown>; headers?: Record<string, string> } = {},
  ): Promise<T> {
    const url = new URL(path, this.baseUrl(service));
    for (const [k, v] of Object.entries(init.query ?? {})) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }

    const started = Date.now();
    let res: Response;
    try {
      res = await this.policy.execute(service, (signal) =>
        fetch(url, {
          method,
          headers: {
            'content-type': 'application/json',
            'x-trace-id': currentTraceId(),
            ...init.headers,
            [PRINCIPAL_HEADER]: req.principalHeaders.value,
            [PRINCIPAL_SIGNATURE_HEADER]: req.principalHeaders.signature,
          },
          body: init.body ? JSON.stringify(init.body) : undefined,
          signal,
        }),
      );
    } catch (err) {
      if (err instanceof CircuitOpenError) {
        throw new HttpException(
          { title: 'Upstream unavailable', status: HttpStatus.SERVICE_UNAVAILABLE },
          HttpStatus.SERVICE_UNAVAILABLE,
        );
      }
      if (isTimeoutError(err)) {
        throw new HttpException(
          { title: 'Upstream timeout', status: HttpStatus.GATEWAY_TIMEOUT },
          HttpStatus.GATEWAY_TIMEOUT,
        );
      }
      if (isRetryableError(err)) {
        throw new HttpException(
          { title: 'Upstream unavailable', status: HttpStatus.SERVICE_UNAVAILABLE },
          HttpStatus.SERVICE_UNAVAILABLE,
        );
      }
      throw err;
    }

    this.log.debug({ service, method, path, status: res.status, ms: Date.now() - started }, 'forwarded');

    const payload = res.status === 204 ? null : await res.json().catch(() => null);
    if (!res.ok) {
      throw new HttpException(payload ?? { title: 'Upstream error', status: res.status }, res.status);
    }
    return payload as T;
  }
}

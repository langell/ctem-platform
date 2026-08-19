import { HttpException, Injectable } from '@nestjs/common';
import { PRINCIPAL_HEADER, PRINCIPAL_SIGNATURE_HEADER } from '@ctem/auth';
import { loadEnv } from '@ctem/config';
import { currentTraceId, rootLogger } from '@ctem/observability';

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
 */
@Injectable()
export class ServiceProxy {
  private readonly log = rootLogger.child({ component: 'proxy' });

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
    init: { body?: unknown; query?: Record<string, unknown> } = {},
  ): Promise<T> {
    const url = new URL(path, this.baseUrl(service));
    for (const [k, v] of Object.entries(init.query ?? {})) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }

    const started = Date.now();
    const res = await fetch(url, {
      method,
      headers: {
        'content-type': 'application/json',
        'x-trace-id': currentTraceId(),
        [PRINCIPAL_HEADER]: req.principalHeaders.value,
        [PRINCIPAL_SIGNATURE_HEADER]: req.principalHeaders.signature,
      },
      body: init.body ? JSON.stringify(init.body) : undefined,
      // TODO: circuit breaker + retry budget before this goes anywhere near production.
      signal: AbortSignal.timeout(30_000),
    });

    this.log.debug({ service, method, path, status: res.status, ms: Date.now() - started }, 'forwarded');

    const payload = res.status === 204 ? null : await res.json().catch(() => null);
    if (!res.ok) {
      throw new HttpException(payload ?? { title: 'Upstream error', status: res.status }, res.status);
    }
    return payload as T;
  }
}

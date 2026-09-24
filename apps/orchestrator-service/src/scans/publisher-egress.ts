import { rootLogger } from '@ctem/observability';
import { InternalHttpPolicy } from '@ctem/resilience';

/**
 * Orchestrator → third-party publisher HTTP (GitHub Checks, GitHub
 * Deployments, GitLab Commit Statuses, GitLab Deployments).
 *
 * Reuses {@link InternalHttpPolicy} from `@ctem/resilience` — the same policy
 * type as api-gateway `ServiceProxy`, not a second breaker. One in-process
 * policy, two circuit names (per allowlisted origin family, not per scan or
 * org):
 *
 * - `egress:github-api` — Checks and Deployment statuses (`api.github.com`)
 * - `egress:gitlab-api` — Commit Statuses and Deployment updates
 *
 * Timeouts and 502/503/504 retries use the platform `CTEM_CB_*` budget (same
 * defaults as the gateway). 4xx is not retried. An open circuit throws
 * `CircuitOpenError` before any fetch.
 *
 * Publishers allowlist the URL before calling this helper, so a refused host
 * never reaches the circuit. `publishForCompletedScan` catches open-circuit
 * and exhausted-retry failures, logs, and returns — the scan and GET
 * conclusions stay unchanged.
 */

export const EGRESS_GITHUB_API = 'egress:github-api';
export const EGRESS_GITLAB_API = 'egress:gitlab-api';

export type PublisherEgressCircuit = typeof EGRESS_GITHUB_API | typeof EGRESS_GITLAB_API;

const log = rootLogger.child({ component: 'publisher-egress' });

let policy: InternalHttpPolicy = InternalHttpPolicy.fromEnv(log);

export function publisherEgressPolicy(): InternalHttpPolicy {
  return policy;
}

/** Tests install a policy with a fake sleep so circuits stay isolated. */
export function usePublisherEgressPolicy(next: InternalHttpPolicy): void {
  policy = next;
}

/**
 * Rebuild from allowlisted `CTEM_CB_*`. Unknown or invalid values throw
 * (fail closed) and leave the previous policy in place.
 */
export function resetPublisherEgressPolicy(source: NodeJS.ProcessEnv = process.env): InternalHttpPolicy {
  const next = InternalHttpPolicy.fromEnv(log, source);
  policy = next;
  return next;
}

export async function publisherEgressJson(
  circuit: PublisherEgressCircuit,
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
): Promise<{ ok: boolean; status: number; json: unknown }> {
  const res = await policy.execute(circuit, (signal) =>
    fetch(url, {
      method: init.method,
      body: init.body,
      headers: init.headers,
      signal,
    }),
  );
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  return { ok: res.ok, status: res.status, json };
}

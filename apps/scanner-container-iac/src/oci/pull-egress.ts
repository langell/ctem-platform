import { rootLogger } from '@ctem/observability';
import { InternalHttpPolicy } from '@ctem/resilience';

/**
 * scanner-container-iac → OCI registry HTTP (manifest, blob, registry auth).
 *
 * Reuses {@link InternalHttpPolicy} from `@ctem/resilience` — the same policy
 * type as the gateway, publisher egress, and notification egress, not a
 * second breaker. One in-process policy, one circuit per registry egress
 * family (not per scan or org):
 *
 * - `egress:ghcr-registry` — ghcr.io token, manifest, blob
 * - `egress:ecr-registry` — ECR GetAuthorizationToken, manifest, blob
 * - `egress:gcr-registry` — Artifact Registry docker token, manifest, blob
 * - `egress:acr-registry` — ACR oauth exchange / token, manifest, blob
 * - `egress:dockerhub-registry` — auth.docker.io token, registry-1 manifest, blob
 * - `egress:quay-registry` — quay.io `/v2/auth`, manifest, blob
 *
 * Callers allowlist the URL before this helper, so a refused host never
 * reaches the circuit and does not trip it. Blob redirects stay on the
 * caller's existing allowlist; this helper does not follow a Location itself.
 *
 * Timeouts and 502/503/504 retries use the platform `CTEM_CB_*` budget (same
 * defaults as the gateway). 4xx is not retried. An open circuit throws
 * `CircuitOpenError` before fetch. Callers already fail the container job on
 * pull/HTTP failure; an open circuit or an exhausted retry does the same
 * (no partial layer inventory). Knobs are not tenant-writable.
 *
 * Google OAuth (`oauth2.googleapis.com`) and Azure AD
 * (`login.microsoftonline.com`) are not registry hosts. Those exchanges stay
 * on their own allowlisted fetch and do not share these circuits.
 */

export const EGRESS_GHCR_REGISTRY = 'egress:ghcr-registry';
export const EGRESS_ECR_REGISTRY = 'egress:ecr-registry';
export const EGRESS_GCR_REGISTRY = 'egress:gcr-registry';
export const EGRESS_ACR_REGISTRY = 'egress:acr-registry';
export const EGRESS_DOCKERHUB_REGISTRY = 'egress:dockerhub-registry';
export const EGRESS_QUAY_REGISTRY = 'egress:quay-registry';

export const REGISTRY_EGRESS_CIRCUITS = [
  EGRESS_GHCR_REGISTRY,
  EGRESS_ECR_REGISTRY,
  EGRESS_GCR_REGISTRY,
  EGRESS_ACR_REGISTRY,
  EGRESS_DOCKERHUB_REGISTRY,
  EGRESS_QUAY_REGISTRY,
] as const;

export type RegistryEgressCircuit = (typeof REGISTRY_EGRESS_CIRCUITS)[number];

const log = rootLogger.child({ component: 'registry-pull-egress' });

let policy: InternalHttpPolicy = InternalHttpPolicy.fromEnv(log);

export function registryPullPolicy(): InternalHttpPolicy {
  return policy;
}

/** Tests install a policy with a fake sleep so circuits stay isolated. */
export function useRegistryPullPolicy(next: InternalHttpPolicy): void {
  policy = next;
}

/**
 * Rebuild from allowlisted `CTEM_CB_*`. Unknown or invalid values throw
 * (fail closed) and leave the previous policy in place.
 */
export function resetRegistryPullPolicy(
  source: NodeJS.ProcessEnv = process.env,
): InternalHttpPolicy {
  const next = InternalHttpPolicy.fromEnv(log, source);
  policy = next;
  return next;
}

/**
 * One registry HTTP attempt budget. `init.signal` is replaced by the policy
 * timeout (`CTEM_CB_TIMEOUT_MS`) so a dead registry cannot hang past the
 * platform knob.
 */
export async function registryPullFetch(
  circuit: RegistryEgressCircuit,
  url: string,
  init: RequestInit,
  fetchImpl: typeof fetch = fetch,
): Promise<Response> {
  return policy.execute(circuit, (signal) => fetchImpl(url, { ...init, signal }));
}

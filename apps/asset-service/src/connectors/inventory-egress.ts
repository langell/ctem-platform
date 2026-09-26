import { rootLogger } from '@ctem/observability';
import { InternalHttpPolicy } from '@ctem/resilience';

/**
 * Asset-service → third-party discovery HTTP.
 *
 * Reuses {@link InternalHttpPolicy} from `@ctem/resilience` — the same policy
 * type as api-gateway `ServiceProxy`, orchestrator publisher egress, and
 * notification Slack/Jira, not a second breaker. One in-process policy and
 * one circuit per platform-fixed egress family (not per org, not per
 * connector instance):
 *
 * - `egress:github-api` — GitHub repos and GHCR Packages REST (`api.github.com`)
 * - `egress:gitlab-api`
 * - `egress:aws-api` — AWS inventory and ECR discovery (including their STS calls)
 * - `egress:gcp-api` — GCP inventory, Artifact Registry, and the GCP token exchange
 * - `egress:azure-api` — ARM, ACR, and the Azure token exchange
 * - `egress:dockerhub-api`
 * - `egress:quay-api`
 * - `egress:dns-ct` — crt.sh
 * - `egress:k8s-controlplane` — EKS / GKE / AKS control-plane calls, including
 *   the STS GetCallerIdentity the EKS path uses. Azure and GCP token exchanges
 *   stay on `egress:azure-api` / `egress:gcp-api` even when Kubernetes calls them.
 *
 * Timeouts and 502/503/504 retries use the platform `CTEM_CB_*` budget (default
 * 3 attempts). 4xx is not retried. An open circuit throws `CircuitOpenError`
 * before any fetch. Callers allowlist the URL before this helper, so a refused
 * host never reaches the circuit. An open circuit or exhausted failure
 * propagates so the sync fails closed (no partial archive, no silent success).
 */

export const EGRESS_GITHUB_API = 'egress:github-api';
export const EGRESS_GITLAB_API = 'egress:gitlab-api';
export const EGRESS_AWS_API = 'egress:aws-api';
export const EGRESS_GCP_API = 'egress:gcp-api';
export const EGRESS_AZURE_API = 'egress:azure-api';
export const EGRESS_DOCKERHUB_API = 'egress:dockerhub-api';
export const EGRESS_QUAY_API = 'egress:quay-api';
export const EGRESS_DNS_CT = 'egress:dns-ct';
export const EGRESS_K8S_CONTROLPLANE = 'egress:k8s-controlplane';

export type InventoryEgressCircuit =
  | typeof EGRESS_GITHUB_API
  | typeof EGRESS_GITLAB_API
  | typeof EGRESS_AWS_API
  | typeof EGRESS_GCP_API
  | typeof EGRESS_AZURE_API
  | typeof EGRESS_DOCKERHUB_API
  | typeof EGRESS_QUAY_API
  | typeof EGRESS_DNS_CT
  | typeof EGRESS_K8S_CONTROLPLANE;

const log = rootLogger.child({ component: 'inventory-egress' });

let policy: InternalHttpPolicy = InternalHttpPolicy.fromEnv(log);

export function inventoryEgressPolicy(): InternalHttpPolicy {
  return policy;
}

/** Tests install a policy with a fake sleep so circuits stay isolated. */
export function useInventoryEgressPolicy(next: InternalHttpPolicy): void {
  policy = next;
}

/**
 * Rebuild from allowlisted `CTEM_CB_*`. Unknown or invalid values throw
 * (fail closed) and leave the previous policy in place.
 */
export function resetInventoryEgressPolicy(
  source: NodeJS.ProcessEnv = process.env,
): InternalHttpPolicy {
  const next = InternalHttpPolicy.fromEnv(log, source);
  policy = next;
  return next;
}

export interface InventoryEgressRequest {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  redirect?: 'error' | 'follow' | 'manual';
}

/**
 * Discovery HTTP on a family circuit. Allowlist first — this function does
 * not check hosts, and a refusal must not be routed here.
 */
export async function inventoryEgressFetch(
  circuit: InventoryEgressCircuit,
  url: string,
  init: InventoryEgressRequest = {},
): Promise<Response> {
  return inventoryEgressExecute(circuit, (signal) => {
    const request: RequestInit = { signal };
    if (init.method !== undefined) request.method = init.method;
    if (init.headers !== undefined) request.headers = init.headers;
    if (init.body !== undefined) request.body = init.body;
    if (init.redirect !== undefined) request.redirect = init.redirect;
    return fetch(url, request);
  });
}

/**
 * Same policy for callers that are not `fetch` (crt.sh pinned HTTPS).
 * The attempt must honor `signal` so `CTEM_CB_TIMEOUT_MS` aborts a hang.
 * Allowlist still happens in the caller, before this function.
 */
export async function inventoryEgressExecute(
  circuit: InventoryEgressCircuit,
  attempt: (signal: AbortSignal) => Promise<Response>,
): Promise<Response> {
  return policy.execute(circuit, attempt);
}

import { SEVERITY_ORDER, type Severity } from '../common';
import type { PolicyCondition } from './policy';
import type { ScanConclusion, ScanDeployConclusion } from './scan';

/**
 * CI-facing scan gate, distinct from job `status`.
 *
 * Only a matching tenant `fail_build` policy can produce `failed`. Callers
 * (PAT/JWT) cannot POST or PATCH this field — GET computes it. GitHub Checks
 * reuse this function; they do not take a client conclusion.
 *
 * Deploy tooling polls `concludeDeploy` on the same inputs. That gate looks
 * only for `block_deploy` and never overloads this function. GitHub Deployment
 * statuses reuse `concludeDeploy`; they do not take a client conclusion.
 * GitLab Deployment updates reuse the same `concludeDeploy` result.
 */

export interface PolicyMatchFinding {
  id: string;
  severity: string;
  riskScore: number;
  kev: boolean;
  epssScore: number | null;
  fixAvailable: boolean;
  scannerType: string;
  asset: { kind: string; exposure: string; criticality: string; tags: unknown };
}

export interface PolicyMatchRule {
  enabled?: boolean;
  priority: number;
  condition: PolicyCondition;
  actions: string[];
}

/** Shared with the risk-service engine so GET conclusion cannot drift. */
export function matchesPolicyCondition(
  condition: PolicyCondition,
  finding: PolicyMatchFinding,
): boolean {
  if (
    condition.severityAtLeast &&
    SEVERITY_ORDER[finding.severity as Severity] < SEVERITY_ORDER[condition.severityAtLeast]
  ) {
    return false;
  }
  if (condition.minRiskScore !== undefined && finding.riskScore < condition.minRiskScore) {
    return false;
  }
  if (condition.kevOnly && !finding.kev) return false;
  if (condition.minEpss !== undefined && (finding.epssScore ?? 0) < condition.minEpss) {
    return false;
  }
  if (condition.requireFixAvailable && !finding.fixAvailable) return false;
  if (condition.scannerTypes?.length && !condition.scannerTypes.includes(finding.scannerType)) {
    return false;
  }
  if (condition.assetKinds?.length && !condition.assetKinds.includes(finding.asset.kind)) {
    return false;
  }
  if (condition.exposure?.length && !condition.exposure.includes(finding.asset.exposure)) {
    return false;
  }
  if (condition.criticality?.length && !condition.criticality.includes(finding.asset.criticality)) {
    return false;
  }
  if (condition.assetTags) {
    const tags = (finding.asset.tags ?? {}) as Record<string, string>;
    for (const [k, v] of Object.entries(condition.assetTags)) {
      if (tags[k] !== v) return false;
    }
  }
  return true;
}

export interface ConcludePolicyInput {
  status: string;
  findings: PolicyMatchFinding[];
  policies: PolicyMatchRule[];
  suppressedFindingIds?: Iterable<string>;
  expectedFindingCount?: number;
}

/**
 * Shared matching loop for GET gates. First matching enabled policy wins per
 * finding (same as the engine). Parameterized by the winning action so
 * `concludeScan` and `concludeDeploy` cannot drift.
 */
function concludeByAction<T extends string>(
  input: ConcludePolicyInput,
  action: string,
  outcomes: { pending: T; matched: T; unmatched: T },
): T {
  if (input.status === 'queued' || input.status === 'running') return outcomes.pending;
  if ((input.expectedFindingCount ?? 0) > 0 && input.findings.length === 0) return outcomes.pending;

  const suppressed = new Set(input.suppressedFindingIds ?? []);
  const policies = input.policies
    .filter((policy) => policy.enabled !== false)
    .slice()
    .sort((a, b) => a.priority - b.priority);

  for (const finding of input.findings) {
    if (suppressed.has(finding.id)) continue;
    for (const policy of policies) {
      if (!matchesPolicyCondition(policy.condition, finding)) continue;
      if (policy.actions.includes(action)) return outcomes.matched;
      break;
    }
  }
  return outcomes.unmatched;
}

/**
 * First matching enabled policy wins per finding (same as the engine).
 * There is no `clientConclusion` argument — a POST body cannot fail the build.
 * Only inspects `fail_build`. Do not overload this to mean deploy as well.
 */
export function concludeScan(input: ConcludePolicyInput): ScanConclusion {
  return concludeByAction(input, 'fail_build', {
    pending: 'pending',
    matched: 'failed',
    unmatched: 'passed',
  });
}

/**
 * Deploy gate parallel to `concludeScan`. Same pending rules and first-match
 * priority sort; looks only for `block_deploy`. A matching `fail_build` alone
 * does not block deploy.
 */
export function concludeDeploy(input: ConcludePolicyInput): ScanDeployConclusion {
  return concludeByAction(input, 'block_deploy', {
    pending: 'pending',
    matched: 'blocked',
    unmatched: 'allowed',
  });
}

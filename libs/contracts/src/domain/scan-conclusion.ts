import { SEVERITY_ORDER, type Severity } from '../common';
import type { PolicyCondition } from './policy';
import type { ScanConclusion } from './scan';

/**
 * CI-facing scan gate, distinct from job `status`.
 *
 * Only a matching tenant `fail_build` policy can produce `failed`. Callers
 * (PAT/JWT) cannot POST or PATCH this field — GET computes it.
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

/**
 * First matching enabled policy wins per finding (same as the engine).
 * There is no `clientConclusion` argument — a POST body cannot fail the build.
 */
export function concludeScan(input: {
  status: string;
  findings: PolicyMatchFinding[];
  policies: PolicyMatchRule[];
  suppressedFindingIds?: Iterable<string>;
  expectedFindingCount?: number;
}): ScanConclusion {
  if (input.status === 'queued' || input.status === 'running') return 'pending';
  if ((input.expectedFindingCount ?? 0) > 0 && input.findings.length === 0) return 'pending';

  const suppressed = new Set(input.suppressedFindingIds ?? []);
  const policies = input.policies
    .filter((policy) => policy.enabled !== false)
    .slice()
    .sort((a, b) => a.priority - b.priority);

  for (const finding of input.findings) {
    if (suppressed.has(finding.id)) continue;
    for (const policy of policies) {
      if (!matchesPolicyCondition(policy.condition, finding)) continue;
      if (policy.actions.includes('fail_build')) return 'failed';
      break;
    }
  }
  return 'passed';
}

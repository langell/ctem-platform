/**
 * Platform seed rule — not a policy editor. When no tenant policy matched,
 * KEV or critical still emits `ctem.policy.violated` with `notify` so the
 * Slack loop actually fires (demo seed has no policy rows today).
 */

export const SEED_KEV_OR_CRITICAL_POLICY_ID = '00000000-0000-4000-8000-00000000c7e1';

export const SEED_NOTIFY_ACTIONS = ['notify'] as const;

export function matchesSeedKevOrCritical(finding: { kev: boolean; severity: string }): boolean {
  return finding.kev === true || finding.severity === 'critical';
}

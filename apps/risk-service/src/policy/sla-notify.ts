/**
 * Reset rules for findings.slaNotifiedAt — the durable SLA breach notify-once
 * claim. A later window may publish ctem.policy.sla_breached again only after
 * this column is cleared.
 *
 * Clear when:
 * - the finding is resolved (triage or ingest auto-resolve)
 * - slaDueAt is set to null
 * - slaDueAt moves later than the previous due (new or extended window)
 *
 * Resolve→reopen starts from a null claim (cleared on resolve). Tightening the
 * due (earlier or equal) does not re-arm. Other terminal states (risk_accepted,
 * false_positive, suppressed) are out of the sweep and do not reset.
 */
export function slaNotifyResetForDueChange(
  previousDue: Date | null | undefined,
  nextDue: Date | null,
): { slaNotifiedAt: null } | Record<string, never> {
  if (nextDue === null) return { slaNotifiedAt: null };
  if (previousDue != null && nextDue.getTime() > previousDue.getTime()) {
    return { slaNotifiedAt: null };
  }
  return {};
}

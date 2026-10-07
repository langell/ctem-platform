/** At most this many invite emails per org per rolling 24 hours (lock item 38). */
export const INVITE_EMAIL_DAILY_CAP = 50;

export const INVITE_EMAIL_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * Counts invite emails already issued for an org inside the rolling window.
 * Slice B adds `membership_invites.lastIssuedAt`. This package does not query
 * invite rows; create/resend wiring supplies the count.
 */
export interface InviteEmailCap {
  countIssuedInWindow(orgId: string, now: Date): Promise<number>;
}

/** Over the cap the invite is still created; only the email is skipped. */
export function inviteEmailCapDecision(issuedInWindow: number): 'send' | 'skipped' {
  return issuedInWindow >= INVITE_EMAIL_DAILY_CAP ? 'skipped' : 'send';
}

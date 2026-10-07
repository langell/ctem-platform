import { inviteEmailCapDecision } from './invite-email-cap';
import type { EmailDelivery, InviteMailer, InviteMailInput } from './invite-mailer';

export interface InviteMailLog {
  warn(fields: { inviteId: string; code: string }, message: string): void;
}

/**
 * Fields safe to log when SMTP refuses a send. Never the link, token, hash, or body.
 * `code` is copied only when it looks like an SMTP/Node error code.
 */
export function inviteMailFailureFields(
  inviteId: string,
  err: unknown,
): { inviteId: string; code: string } {
  let code = 'SEND_FAILED';
  if (err && typeof err === 'object' && 'code' in err) {
    const value = (err as { code: unknown }).code;
    if (typeof value === 'string' && /^[A-Z0-9_]{1,64}$/.test(value)) code = value;
  }
  return { inviteId, code };
}

/**
 * Send after the create/resend transaction commits. A failure or the daily cap
 * does not roll back the invite. Slice B's OrgService call sites use this;
 * they are not wired in this change.
 */
export async function sendInviteEmail(input: {
  mailer: InviteMailer;
  message: InviteMailInput;
  inviteId: string;
  issuedInWindow: number;
  log: InviteMailLog;
}): Promise<EmailDelivery> {
  if (inviteEmailCapDecision(input.issuedInWindow) === 'skipped') return 'skipped';
  try {
    await input.mailer.send(input.message);
    return 'sent';
  } catch (err) {
    input.log.warn(inviteMailFailureFields(input.inviteId, err), 'invite email failed');
    return 'failed';
  }
}

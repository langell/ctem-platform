/**
 * Invite mail port. Identity calls this after a create or resend transaction
 * commits. Slice B owns those call sites; this package only defines the port.
 * The raw token belongs in the accept URL the caller passes in, never in a log.
 */

export interface InviteMailInput {
  to: string;
  orgName: string;
  role: string;
  /** `${CTEM_ORIGIN}/invite#token=ctem_inv_…`. The fragment never hits a server log. */
  acceptUrl: string;
  expiresAt: Date;
}

export interface InviteMailer {
  send(message: InviteMailInput): Promise<void>;
}

export const INVITE_MAILER = Symbol('INVITE_MAILER');

/** Result the create/resend response will expose once Slice B wires the call sites. */
export type EmailDelivery = 'sent' | 'skipped' | 'failed';

import type { InviteMailer, InviteMailInput } from './invite-mailer';

/**
 * CTEM_MAIL_TRANSPORT=none. Sends nothing and does not log the recipient,
 * link, token, or body. CI and production use this until SMTP is configured.
 */
export class NullInviteMailer implements InviteMailer {
  async send(_message: InviteMailInput): Promise<void> {
    // Intentionally empty.
  }
}

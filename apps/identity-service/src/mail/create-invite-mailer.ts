import type { Env } from '@ctem/config';
import type { InviteMailer } from './invite-mailer';
import { NullInviteMailer } from './null-invite-mailer';
import { SmtpInviteMailer } from './smtp-invite-mailer';

export type MailEnv = Pick<
  Env,
  | 'CTEM_MAIL_TRANSPORT'
  | 'CTEM_SMTP_HOST'
  | 'CTEM_SMTP_PORT'
  | 'CTEM_SMTP_SECURITY'
  | 'CTEM_SMTP_USER'
  | 'CTEM_SMTP_PASSWORD'
  | 'CTEM_MAIL_FROM'
>;

/** `none` → NullInviteMailer. `smtp` → generic SMTP. Anything else fails closed. */
export function createInviteMailer(env: MailEnv): InviteMailer {
  if (env.CTEM_MAIL_TRANSPORT === 'none') return new NullInviteMailer();
  if (env.CTEM_MAIL_TRANSPORT === 'smtp') return SmtpInviteMailer.fromEnv(env);
  throw new Error('Unsupported CTEM_MAIL_TRANSPORT');
}

import { Module } from '@nestjs/common';
import { CtemConfigModule, ENV, type Env } from '@ctem/config';
import { createInviteMailer } from './create-invite-mailer';
import { INVITE_MAILER, type InviteMailer } from './invite-mailer';

/**
 * Selects NullInviteMailer or SmtpInviteMailer from CTEM_MAIL_TRANSPORT.
 * OrgService does not call the port yet: create and resend wiring waits
 * until Slice B merges (lock item 39).
 */
@Module({
  imports: [CtemConfigModule],
  providers: [
    {
      provide: INVITE_MAILER,
      inject: [ENV],
      useFactory: (env: Env): InviteMailer => createInviteMailer(env),
    },
  ],
  exports: [INVITE_MAILER],
})
export class MailModule {}

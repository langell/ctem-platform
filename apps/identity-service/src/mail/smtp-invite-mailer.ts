import type { OnModuleDestroy } from '@nestjs/common';
import type { Env } from '@ctem/config';
import { createTransport, type SMTPTransportOptions, type Transporter } from 'nodemailer';
import type { InviteMailer, InviteMailInput } from './invite-mailer';
import { renderInviteEmail } from './invite-template';

export type SmtpEnv = Pick<
  Env,
  | 'CTEM_SMTP_HOST'
  | 'CTEM_SMTP_PORT'
  | 'CTEM_SMTP_SECURITY'
  | 'CTEM_SMTP_USER'
  | 'CTEM_SMTP_PASSWORD'
  | 'CTEM_MAIL_FROM'
>;

/** Minimal transport so tests can capture a send without opening a socket. */
export interface OutboundMail {
  sendMail(message: {
    from: string;
    to: string;
    subject: string;
    text: string;
    html: string;
    disableFileAccess: true;
    disableUrlAccess: true;
  }): Promise<unknown>;
  close(): void;
}

/**
 * Generic SMTP. Logger, debug, and transaction logging stay off so the
 * message body and token never hit nodemailer's logger. No provider SDK.
 */
export function smtpTransportOptions(env: SmtpEnv): SMTPTransportOptions {
  const user = env.CTEM_SMTP_USER?.trim() ?? '';
  const security = env.CTEM_SMTP_SECURITY;
  return {
    host: env.CTEM_SMTP_HOST,
    port: env.CTEM_SMTP_PORT,
    secure: security === 'tls',
    requireTLS: security === 'starttls',
    ignoreTLS: security === 'none',
    auth: user ? { user, pass: env.CTEM_SMTP_PASSWORD ?? '' } : undefined,
    logger: false,
    debug: false,
    transactionLog: false,
  };
}

export function createSmtpTransport(env: SmtpEnv): Transporter {
  return createTransport(smtpTransportOptions(env));
}

export class SmtpInviteMailer implements InviteMailer, OnModuleDestroy {
  constructor(
    private readonly transport: OutboundMail,
    private readonly from: string,
  ) {}

  static fromEnv(env: SmtpEnv): SmtpInviteMailer {
    return new SmtpInviteMailer(createSmtpTransport(env), env.CTEM_MAIL_FROM);
  }

  async send(message: InviteMailInput): Promise<void> {
    const rendered = renderInviteEmail(message);
    await this.transport.sendMail({
      from: this.from,
      to: message.to,
      subject: rendered.subject,
      text: rendered.text,
      html: rendered.html,
      disableFileAccess: true,
      disableUrlAccess: true,
    });
  }

  onModuleDestroy(): void {
    this.transport.close();
  }
}

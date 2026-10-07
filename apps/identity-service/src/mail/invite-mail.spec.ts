import { describe, expect, it, vi } from 'vitest';
import { createInviteMailer, type MailEnv } from './create-invite-mailer';
import { INVITE_EMAIL_DAILY_CAP, inviteEmailCapDecision } from './invite-email-cap';
import { NullInviteMailer } from './null-invite-mailer';
import { inviteMailFailureFields, sendInviteEmail } from './send-invite-email';
import {
  createSmtpTransport,
  SmtpInviteMailer,
  smtpTransportOptions,
  type OutboundMail,
} from './smtp-invite-mailer';
import { inviteAcceptUrl } from './invite-template';
import type { InviteMailInput } from './invite-mailer';

const TOKEN = `ctem_inv_${'b'.repeat(43)}`;
const FROM = 'CTEM <invites@localhost>';

function message(): InviteMailInput {
  return {
    to: 'invitee@example.com',
    orgName: 'Demo Corp',
    role: 'developer',
    acceptUrl: inviteAcceptUrl('http://localhost:3000', TOKEN),
    expiresAt: new Date('2026-10-21T15:04:05.000Z'),
  };
}

const baseSmtp = {
  CTEM_SMTP_HOST: 'localhost',
  CTEM_SMTP_PORT: 1025,
  CTEM_SMTP_SECURITY: 'none' as const,
  CTEM_SMTP_USER: undefined,
  CTEM_SMTP_PASSWORD: undefined,
  CTEM_MAIL_FROM: FROM,
};

describe('invite mail transport selection', () => {
  it('selects the null mailer when transport is none', () => {
    const mailer = createInviteMailer({ ...baseSmtp, CTEM_MAIL_TRANSPORT: 'none' });
    expect(mailer).toBeInstanceOf(NullInviteMailer);
  });

  it('selects generic SMTP when transport is smtp', () => {
    const mailer = createInviteMailer({ ...baseSmtp, CTEM_MAIL_TRANSPORT: 'smtp' });
    expect(mailer).toBeInstanceOf(SmtpInviteMailer);
    (mailer as SmtpInviteMailer).onModuleDestroy();
  });

  it('fails closed on an unexpected transport', () => {
    expect(() =>
      createInviteMailer({
        ...baseSmtp,
        CTEM_MAIL_TRANSPORT: 'postmark',
      } as MailEnv),
    ).toThrow(/Unsupported CTEM_MAIL_TRANSPORT/);
  });
});

describe('SMTP transport options', () => {
  it('keeps logger, debug, and transaction logging off for Mailpit', () => {
    const options = smtpTransportOptions(baseSmtp);
    expect(options).toMatchObject({
      host: 'localhost',
      port: 1025,
      secure: false,
      requireTLS: false,
      ignoreTLS: true,
      logger: false,
      debug: false,
      transactionLog: false,
    });
    expect(options.auth).toBeUndefined();
    const transport = createSmtpTransport(baseSmtp);
    expect(transport.options.logger).toBe(false);
    expect(transport.options.debug).toBe(false);
    expect(transport.options.transactionLog).toBe(false);
    transport.close();
  });

  it('maps starttls and tls without embedding a provider SDK', () => {
    expect(
      smtpTransportOptions({ ...baseSmtp, CTEM_SMTP_SECURITY: 'starttls', CTEM_SMTP_PORT: 587 }),
    ).toMatchObject({ secure: false, requireTLS: true, ignoreTLS: false, port: 587 });
    expect(
      smtpTransportOptions({ ...baseSmtp, CTEM_SMTP_SECURITY: 'tls', CTEM_SMTP_PORT: 465 }),
    ).toMatchObject({ secure: true, requireTLS: false, ignoreTLS: false, port: 465 });
  });

  it('passes SMTP credentials only when a user is set', () => {
    const options = smtpTransportOptions({
      ...baseSmtp,
      CTEM_SMTP_USER: 'server-token',
      CTEM_SMTP_PASSWORD: 'server-token',
    });
    expect(options.auth).toEqual({ user: 'server-token', pass: 'server-token' });
  });

  it('sends the rendered message and disables remote content fetches', async () => {
    const sent: Array<{ subject?: string; text?: string; html?: string; from?: string }> = [];
    const transport: OutboundMail = {
      async sendMail(mail) {
        sent.push(mail);
      },
      close() {},
    };
    const mailer = new SmtpInviteMailer(transport, FROM);
    await mailer.send(message());
    expect(sent).toHaveLength(1);
    expect(sent[0].from).toBe(FROM);
    expect(sent[0].subject).toBe("You're invited to Demo Corp on CTEM");
    expect(sent[0].subject).not.toContain(TOKEN);
    expect(sent[0].text).toContain(`/invite#token=${TOKEN}`);
    expect(sent[0].html).toContain(`/invite#token=${TOKEN}`);
    expect(sent[0].html).not.toMatch(/<img[\s>]/i);
    expect(sent[0]).toMatchObject({ disableFileAccess: true, disableUrlAccess: true });
  });
});

describe('NullInviteMailer', () => {
  it('resolves without writing the recipient, link, or token', async () => {
    const chunks: string[] = [];
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      chunks.push(String(chunk));
      return true;
    });
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      await new NullInviteMailer().send(message());
      const written = chunks.join('');
      expect(written).not.toContain(TOKEN);
      expect(written).not.toContain('invitee@example.com');
      expect(written).not.toContain('invite#token');
    } finally {
      stdout.mockRestore();
      stderr.mockRestore();
    }
  });
});

describe('invite email cap and failure log', () => {
  it('sends below the daily cap and skips at the cap', () => {
    expect(inviteEmailCapDecision(0)).toBe('send');
    expect(inviteEmailCapDecision(INVITE_EMAIL_DAILY_CAP - 1)).toBe('send');
    expect(inviteEmailCapDecision(INVITE_EMAIL_DAILY_CAP)).toBe('skipped');
    expect(inviteEmailCapDecision(INVITE_EMAIL_DAILY_CAP + 1)).toBe('skipped');
  });

  it('logs only inviteId and an error code', () => {
    const err = new Error(`connect ECONNREFUSED ${message().acceptUrl}`);
    (err as Error & { code: string }).code = 'ECONNREFUSED';
    const fields = inviteMailFailureFields('invite-1', err);
    expect(fields).toEqual({ inviteId: 'invite-1', code: 'ECONNREFUSED' });
    expect(JSON.stringify(fields)).not.toContain('ctem_inv_');

    const stuffed = new Error('nope');
    (stuffed as Error & { code: string }).code = message().acceptUrl;
    expect(inviteMailFailureFields('invite-1', stuffed).code).toBe('SEND_FAILED');
  });

  it('returns failed and does not call the mailer again after a refusal', async () => {
    const lines: unknown[] = [];
    let calls = 0;
    const delivery = await sendInviteEmail({
      mailer: {
        async send() {
          calls += 1;
          const err = new Error(message().acceptUrl);
          (err as Error & { code: string }).code = 'ECONNECTION';
          throw err;
        },
      },
      message: message(),
      inviteId: 'invite-2',
      issuedInWindow: 0,
      log: {
        warn(fields, msg) {
          lines.push(fields, msg);
        },
      },
    });
    expect(delivery).toBe('failed');
    expect(calls).toBe(1);
    expect(lines[0]).toEqual({ inviteId: 'invite-2', code: 'ECONNECTION' });
    expect(JSON.stringify(lines)).not.toContain('ctem_inv_');
  });
});

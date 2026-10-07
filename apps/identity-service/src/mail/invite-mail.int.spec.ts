import { describe, expect, it } from 'vitest';
import type { InviteMailInput, InviteMailer } from './invite-mailer';
import { sendInviteEmail } from './send-invite-email';
import { SmtpInviteMailer, type OutboundMail } from './smtp-invite-mailer';
import { inviteAcceptUrl } from './invite-template';

/**
 * Invite mail send behavior, isolated from OrgService.
 *
 * Create/resend call sites, the HTTP 201 `emailDelivery` response, and the
 * `lastIssuedAt` count wait for Slice B (lock items 39 and 41). Those cases
 * are todos below. This file injects a capture transport and does not read
 * or write invite rows.
 */

const TOKEN = `ctem_inv_${'c'.repeat(43)}`;
const OTHER = `ctem_inv_${'d'.repeat(43)}`;
const FROM = 'CTEM <invites@localhost>';

class CaptureTransport implements OutboundMail {
  readonly messages: Array<{ subject: string; text: string; html: string; to: string }> = [];

  async sendMail(message: {
    from: string;
    to: string;
    subject: string;
    text: string;
    html: string;
  }): Promise<unknown> {
    this.messages.push({
      subject: message.subject,
      text: message.text,
      html: message.html,
      to: message.to,
    });
    return { messageId: 'capture' };
  }

  close(): void {}
}

class CaptureInviteMailer implements InviteMailer {
  readonly sent: InviteMailInput[] = [];

  async send(message: InviteMailInput): Promise<void> {
    this.sent.push(message);
  }
}

function input(token: string): InviteMailInput {
  return {
    to: 'invitee@example.com',
    orgName: 'Demo & Corp',
    role: 'developer',
    acceptUrl: inviteAcceptUrl('http://localhost:3000', token),
    expiresAt: new Date('2026-10-21T00:00:00.000Z'),
  };
}

describe('invite mail send (capture, no OrgService)', () => {
  it('sends one message whose body holds the link and whose subject does not', async () => {
    const capture = new CaptureTransport();
    const mailer = new SmtpInviteMailer(capture, FROM);
    const delivery = await sendInviteEmail({
      mailer,
      message: input(TOKEN),
      inviteId: '00000000-0000-4000-8000-000000000001',
      issuedInWindow: 0,
      log: { warn() {} },
    });
    expect(delivery).toBe('sent');
    expect(capture.messages).toHaveLength(1);
    const sent = capture.messages[0];
    expect(sent.to).toBe('invitee@example.com');
    expect(sent.subject).toBe("You're invited to Demo & Corp on CTEM");
    expect(sent.subject).not.toContain('ctem_inv_');
    expect(sent.text).toContain(`/invite#token=${TOKEN}`);
    expect(sent.text).not.toContain(OTHER);
    expect(sent.html).toContain(`/invite#token=${TOKEN}`);
    expect(sent.html).toContain('Demo &amp; Corp');
    expect(sent.html).not.toMatch(/<img[\s>]/i);
    expect(sent.html).not.toContain('pixel');
  });

  it('a refused send is failed and the warn line has no token', async () => {
    const lines: unknown[] = [];
    const delivery = await sendInviteEmail({
      mailer: {
        async send(message) {
          const err = new Error(`ECONNREFUSED ${message.acceptUrl}`);
          (err as Error & { code: string }).code = 'ECONNREFUSED';
          throw err;
        },
      },
      message: input(TOKEN),
      inviteId: '00000000-0000-4000-8000-000000000002',
      issuedInWindow: 1,
      log: {
        warn(fields, msg) {
          lines.push(fields, msg);
        },
      },
    });
    expect(delivery).toBe('failed');
    expect(lines).toEqual([
      { inviteId: '00000000-0000-4000-8000-000000000002', code: 'ECONNREFUSED' },
      'invite email failed',
    ]);
    expect(JSON.stringify(lines)).not.toContain('ctem_inv_');
    expect(JSON.stringify(lines)).not.toContain('invite#token');
  });

  it('at the daily cap the capture mailer is not called and delivery is skipped', async () => {
    const capture = new CaptureInviteMailer();
    const delivery = await sendInviteEmail({
      mailer: capture,
      message: input(TOKEN),
      inviteId: '00000000-0000-4000-8000-000000000003',
      issuedInWindow: 50,
      log: { warn() {} },
    });
    expect(delivery).toBe('skipped');
    expect(capture.sent).toHaveLength(0);
  });

  // Lock item 41. These need Slice B's create/resend routes and lastIssuedAt
  // (items 28 and 39). Do not invent OrgService wiring in this PR.
  it.todo('create sends one message with the link (lock item 41; after Slice B, item 39)');
  it.todo(
    "resend's message holds the new link and not the old one (lock item 41; after Slice B, item 39)",
  );
  it.todo(
    'SMTP refused returns 201 emailDelivery failed, invite exists, logs have no ctem_inv_ (lock item 41; after Slice B)',
  );
  it.todo(
    'cap reached on create/resend returns skipped and still returns the link (lock items 38 and 41; lastIssuedAt is Slice B)',
  );
});

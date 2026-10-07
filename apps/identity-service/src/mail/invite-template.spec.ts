import { describe, expect, it } from 'vitest';
import { inviteAcceptUrl, renderInviteEmail } from './invite-template';

const TOKEN = `ctem_inv_${'A'.repeat(43)}`;
const ORIGIN = 'http://localhost:3000';
const ACCEPT_URL = `${ORIGIN}/invite#token=${TOKEN}`;

describe('invite email template', () => {
  it('builds the accept link in the fragment and strips one trailing slash', () => {
    expect(inviteAcceptUrl(ORIGIN, TOKEN)).toBe(ACCEPT_URL);
    expect(inviteAcceptUrl(`${ORIGIN}/`, TOKEN)).toBe(ACCEPT_URL);
    expect(ACCEPT_URL).not.toContain('?');
    expect(ACCEPT_URL).toContain('/invite#token=');
  });

  it('refuses a malformed token without echoing it', () => {
    const leaked = 'ctem_inv_not-a-real-token';
    expect(() => inviteAcceptUrl(ORIGIN, leaked)).toThrow(/malformed/);
    try {
      inviteAcceptUrl(ORIGIN, leaked);
    } catch (err) {
      expect((err as Error).message).not.toContain('ctem_inv_');
    }
  });

  it('puts the link and expiry in text and HTML, and never the token in the subject', () => {
    const rendered = renderInviteEmail({
      to: 'invitee@example.com',
      orgName: 'Acme & Sons <lab>',
      role: 'developer',
      acceptUrl: ACCEPT_URL,
      expiresAt: new Date('2026-10-21T00:00:00.000Z'),
    });
    expect(rendered.subject).toBe("You're invited to Acme & Sons <lab> on CTEM");
    expect(rendered.subject).not.toContain(TOKEN);
    expect(rendered.subject).not.toContain('ctem_inv_');
    expect(rendered.text).toContain(ACCEPT_URL);
    expect(rendered.text).toContain('2026-10-21T00:00:00.000Z');
    expect(rendered.text).toContain('as developer');
    expect(rendered.html).toContain(`href="${ACCEPT_URL}"`);
    expect(rendered.html).toContain(ACCEPT_URL);
    expect(rendered.html).toContain('2026-10-21T00:00:00.000Z');
    expect(rendered.html).toContain('Acme &amp; Sons &lt;lab&gt;');
    expect(rendered.html).not.toContain('Acme & Sons');
  });

  it('HTML-escapes a hostile org name so it cannot become a tracking pixel', () => {
    const rendered = renderInviteEmail({
      to: 'invitee@example.com',
      orgName: '<img src="https://evil.test/pixel.gif" />',
      role: 'admin" onmouseover="x',
      acceptUrl: ACCEPT_URL,
      expiresAt: new Date('2026-10-21T00:00:00.000Z'),
    });
    expect(rendered.html).not.toMatch(/<img[\s>]/i);
    expect(rendered.html).not.toMatch(/<script/i);
    expect(rendered.html).toContain('&lt;img src=&quot;https://evil.test/pixel.gif&quot; /&gt;');
    expect(rendered.html).toContain('admin&quot; onmouseover=&quot;x');
    expect(rendered.subject).not.toContain(TOKEN);
    expect(rendered.subject).not.toMatch(/[\r\n]/);
  });

  it('strips header breaks out of the subject', () => {
    const rendered = renderInviteEmail({
      to: 'invitee@example.com',
      orgName: 'Acme\r\nBcc: evil@example.com',
      role: 'developer',
      acceptUrl: ACCEPT_URL,
      expiresAt: new Date('2026-10-21T00:00:00.000Z'),
    });
    expect(rendered.subject).toBe("You're invited to Acme Bcc: evil@example.com on CTEM");
    expect(rendered.subject).not.toMatch(/[\r\n]/);
    expect(rendered.subject).not.toContain(TOKEN);
  });

  it('rejects an accept URL that is not the invite fragment', () => {
    expect(() =>
      renderInviteEmail({
        to: 'invitee@example.com',
        orgName: 'Acme',
        role: 'developer',
        acceptUrl: `${ORIGIN}/invite?token=${TOKEN}`,
        expiresAt: new Date('2026-10-21T00:00:00.000Z'),
      }),
    ).toThrow(/malformed/);
  });
});

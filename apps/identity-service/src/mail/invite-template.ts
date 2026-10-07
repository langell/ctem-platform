import { originOnlyIssue } from '@ctem/config';
import type { InviteMailInput } from './invite-mailer';

const INVITE_TOKEN = /^ctem_inv_[A-Za-z0-9_-]{43}$/;

export interface RenderedInvite {
  subject: string;
  text: string;
  html: string;
}

/** Accept link. The token stays in the fragment and is not placed in a query or path. */
export function inviteAcceptUrl(origin: string, token: string): string {
  const issue = originOnlyIssue(origin);
  if (issue) throw new Error(`CTEM_ORIGIN ${issue}`);
  if (!INVITE_TOKEN.test(token)) throw new Error('invite token is malformed');
  const base = origin.replace(/\/$/, '');
  return `${base}/invite#token=${token}`;
}

export function renderInviteEmail(message: InviteMailInput): RenderedInvite {
  const acceptUrl = canonicalAcceptUrl(message.acceptUrl);
  const expires = message.expiresAt.toISOString();
  const subject = `You're invited to ${subjectOrgName(message.orgName)} on CTEM`;
  const text = [
    `You're invited to ${message.orgName} on CTEM as ${message.role}.`,
    '',
    'Accept the invite:',
    acceptUrl,
    '',
    `This invite expires ${expires}.`,
  ].join('\n');
  const html = [
    '<p>',
    escapeHtml(`You're invited to `),
    escapeHtml(message.orgName),
    escapeHtml(` on CTEM as ${message.role}.`),
    '</p>',
    '<p><a href="',
    escapeHtml(acceptUrl),
    '">',
    escapeHtml(acceptUrl),
    '</a></p>',
    '<p>',
    escapeHtml(`This invite expires ${expires}.`),
    '</p>',
  ].join('');
  return { subject, text, html };
}

function subjectOrgName(orgName: string): string {
  let out = '';
  let skipping = false;
  for (const char of orgName) {
    const code = char.charCodeAt(0);
    if (code <= 0x1f || code === 0x7f) {
      if (!skipping) out += ' ';
      skipping = true;
    } else {
      skipping = false;
      out += char;
    }
  }
  return out;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/**
 * The only link in the body is `${origin}/invite#token=<ctem_inv_…>`.
 * Errors never echo the token.
 */
function canonicalAcceptUrl(acceptUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(acceptUrl);
  } catch {
    throw new Error('accept URL is malformed');
  }
  if (parsed.username || parsed.password || parsed.search) {
    throw new Error('accept URL is malformed');
  }
  if (parsed.pathname !== '/invite') throw new Error('accept URL is malformed');
  const token = parsed.hash.startsWith('#token=') ? parsed.hash.slice('#token='.length) : '';
  if (!INVITE_TOKEN.test(token)) throw new Error('accept URL is malformed');
  const canonical = `${parsed.protocol}//${parsed.host}/invite#token=${token}`;
  if (acceptUrl !== canonical) throw new Error('accept URL is malformed');
  return canonical;
}

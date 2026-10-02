/**
 * Allowlisted Bitbucket Cloud build-status context on the scan row
 * (`options.bitbucket` or the same keys at the top level of `options`).
 * Client keys that set a CI conclusion stay refused on create
 * (`CLIENT_CONCLUSION_KEYS`); any nested `conclusion` / `state` here is
 * ignored — `concludeScan` is the only source.
 *
 * Required to publish:
 *   - `workspace` — Bitbucket workspace id/slug (`[\w.-]+`), not a URL or host
 *   - `repoSlug` (or `repository`) — repo slug id (`[\w.-]+`), not a URL
 *   - `sha` — full 40-char commit SHA
 * Optional:
 *   - `key` — build-status key (default `ctem-scan-{scanId}`); Bitbucket upserts by key
 *   - `name` — display name (default `CTEM`)
 *   - `description` — extra text; published body always includes `scanId`
 *   - `url` — must be a CTEM URL (`CTEM_PUBLIC_URL` origin + scan path) or omit
 *
 * Tenant `baseUrl` / `apiUrl` / `bitbucketHost` (and other
 * `TENANT_BITBUCKET_HOST_KEYS`) on the scan are ignored and never used as the
 * API host. The only origin is exact `api.bitbucket.org`.
 */

import { allowlistedCtemDetailsUrl } from './github-checks.context';
import { assertBitbucketRepoSlug, assertBitbucketWorkspace } from './bitbucket-statuses.egress';

export const DEFAULT_STATUS_NAME = 'CTEM';

const FULL_SHA = /^[0-9a-f]{40}$/i;
const STATUS_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/;

export interface BitbucketStatusesContext {
  workspace: string;
  repoSlug: string;
  sha: string;
  key: string;
  name: string;
  description?: string;
  url?: string;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function stringField(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : undefined;
}

function looksLikeUrl(value: string): boolean {
  return /:\/\//.test(value) || /@/.test(value);
}

/** Identifier, not a URL and not a host. Invalid values skip the publish. */
export function parseBitbucketWorkspace(value: unknown): string | null {
  return parseBitbucketId(value, 'workspace');
}

export function parseBitbucketRepoSlug(value: unknown): string | null {
  return parseBitbucketId(value, 'repo slug');
}

function parseBitbucketId(value: unknown, label: 'workspace' | 'repo slug'): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || looksLikeUrl(trimmed)) return null;
  try {
    return label === 'workspace'
      ? assertBitbucketWorkspace(trimmed)
      : assertBitbucketRepoSlug(trimmed);
  } catch {
    return null;
  }
}

function parseSha(sha: string | undefined): string | null {
  if (!sha || !FULL_SHA.test(sha)) return null;
  return sha.toLowerCase();
}

/** Stable upsert key. A free-form or URL-shaped key falls back to `ctem-scan-{scanId}`. */
export function bitbucketStatusKey(scanId: string, raw: string | undefined): string {
  const fallback = `ctem-scan-${scanId}`;
  if (!raw) return fallback;
  const key = raw.replace(/[\r\n\0]/g, '').trim();
  if (!key || looksLikeUrl(key) || !STATUS_KEY.test(key)) return fallback;
  return key;
}

function sanitizeStatusName(raw: string | undefined): string {
  const name = (raw ?? DEFAULT_STATUS_NAME).replace(/[\r\n\0]/g, ' ').trim();
  if (!name || looksLikeUrl(name)) return DEFAULT_STATUS_NAME;
  return name.slice(0, 100);
}

function parseExtraDescription(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const text = raw.replace(/[\r\n\0]/g, ' ').trim();
  if (!text || looksLikeUrl(text)) return undefined;
  return text.slice(0, 80);
}

export function parseBitbucketStatusesContext(
  options: unknown,
  scanId: string,
): BitbucketStatusesContext | null {
  const opts = asRecord(options);
  const bitbucket = asRecord(opts.bitbucket);
  // Tenant endpoint keys (baseUrl, apiUrl, bitbucketHost, …) are ignored —
  // they must never become the API host.

  const workspace = parseBitbucketWorkspace(bitbucket.workspace ?? opts.workspace);
  const repoSlug = parseBitbucketRepoSlug(
    bitbucket.repoSlug ?? bitbucket.repository ?? opts.repoSlug ?? opts.repository,
  );
  const sha = parseSha(stringField(bitbucket.sha) ?? stringField(opts.sha));
  if (!workspace || !repoSlug || !sha) return null;

  const key = bitbucketStatusKey(scanId, stringField(bitbucket.key) ?? stringField(opts.key));
  const name = sanitizeStatusName(stringField(bitbucket.name) ?? stringField(opts.name));
  const description = parseExtraDescription(
    stringField(bitbucket.description) ?? stringField(opts.description),
  );
  const url = allowlistedCtemDetailsUrl(
    stringField(bitbucket.url) ?? stringField(opts.url),
    scanId,
  );

  return {
    workspace,
    repoSlug,
    sha,
    key,
    name,
    ...(description ? { description } : {}),
    ...(url ? { url } : {}),
  };
}

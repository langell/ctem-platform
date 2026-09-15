/**
 * Allowlisted GitLab CI Commit Status context on the scan row (`options.gitlab`
 * or the same keys at the top level of `options`). Client keys that set a CI
 * conclusion stay refused on create (`CLIENT_CONCLUSION_KEYS`); any nested
 * `conclusion` here is ignored — `concludeScan` is the only source.
 *
 * Required to publish:
 *   - `projectId` — preferred: GitLab `path/with/namespace` (e.g. `acme/api`);
 *     also a positive integer project id. Encoded for the statuses API.
 *   - `sha` — full 40-char commit SHA
 * Optional:
 *   - `name` — status name / context (default `CTEM`); part of idempotent identity
 *   - `description` — extra text; published body always includes `scanId`
 *   - `targetUrl` — must be a CTEM URL (`CTEM_PUBLIC_URL` origin + scan path) or omit
 *   - `ref` — git ref id (branch/tag), never a host
 *
 * Tenant `baseUrl` / `apiUrl` / `EXTRA_GITLAB_HOST_KEYS` on the scan are
 * ignored and never used as the API host. Origin is gitlab.com or the scan
 * asset's GitLab AssetConnector `baseUrl`.
 */

import { allowlistedCtemDetailsUrl } from './github-checks.context';

export const DEFAULT_STATUS_NAME = 'CTEM';

const FULL_SHA = /^[0-9a-f]{40}$/i;
const GITLAB_SEGMENT = /^[\w.-]+$/;

export interface GitlabStatusesContext {
  projectId: string;
  sha: string;
  name: string;
  description?: string;
  targetUrl?: string;
  ref?: string;
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

/**
 * Preferred shape is `path/with/namespace` (what GitLab statuses encode as
 * `:id`). Positive integer project ids are also accepted. URLs / git@ / host
 * strings are refused so `projectId` cannot become an endpoint.
 */
export function parseGitLabProjectId(value: unknown): string | null {
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value <= 0 || value > Number.MAX_SAFE_INTEGER) return null;
    return String(value);
  }
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || looksLikeUrl(trimmed)) return null;
  if (/^[1-9][0-9]{0,15}$/.test(trimmed)) {
    const n = Number(trimmed);
    if (!Number.isInteger(n) || n <= 0 || n > Number.MAX_SAFE_INTEGER) return null;
    return String(n);
  }
  const parts = trimmed.split('/').filter(Boolean);
  if (parts.length < 2 || parts.length > 10) return null;
  if (!parts.every((p) => GITLAB_SEGMENT.test(p) && p !== '.' && p !== '..')) return null;
  return parts.join('/');
}

function parseSha(sha: string | undefined): string | null {
  if (!sha || !FULL_SHA.test(sha)) return null;
  return sha.toLowerCase();
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

/** Git ref id only — never concatenated into an API host. */
function parseGitRef(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const ref = raw.replace(/[\r\n\0]/g, '').trim();
  if (!ref || looksLikeUrl(ref)) return undefined;
  return ref.slice(0, 255);
}

export function parseGitlabStatusesContext(options: unknown, scanId: string): GitlabStatusesContext | null {
  const opts = asRecord(options);
  const gitlab = asRecord(opts.gitlab);
  // Tenant endpoint keys (baseUrl, apiUrl, host, …) are ignored — they must
  // never become the API host.

  const projectId = parseGitLabProjectId(gitlab.projectId ?? opts.projectId);
  const sha = parseSha(stringField(gitlab.sha) ?? stringField(opts.sha));
  if (!projectId || !sha) return null;

  const name = sanitizeStatusName(stringField(gitlab.name) ?? stringField(opts.name));
  const description = parseExtraDescription(
    stringField(gitlab.description) ?? stringField(opts.description),
  );
  const targetUrl = allowlistedCtemDetailsUrl(
    stringField(gitlab.targetUrl) ?? stringField(opts.targetUrl),
    scanId,
  );
  const ref = parseGitRef(stringField(gitlab.ref) ?? stringField(opts.ref));

  return {
    projectId,
    sha,
    name,
    ...(description ? { description } : {}),
    ...(targetUrl ? { targetUrl } : {}),
    ...(ref ? { ref } : {}),
  };
}

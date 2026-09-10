/**
 * Allowlisted GitHub Checks context on the scan row (`options.github` or the
 * same keys at the top level of `options`). Client keys that set a Check
 * conclusion stay refused on create (`CLIENT_CONCLUSION_KEYS`); any nested
 * `conclusion` here is ignored — `concludeScan` is the only source.
 *
 * Required to publish:
 *   - `repository` — `owner/name` (or `owner` + `repo`)
 *   - `sha` — full 40-char commit SHA
 * Optional:
 *   - `checkName` — Check Run name (default `CTEM`); part of idempotent identity
 *   - `detailsUrl` — must be a CTEM URL (`CTEM_PUBLIC_URL` origin + scan path) or omit
 *
 * Tenant `baseUrl` / GHE host keys are ignored and never used as the API host.
 */
export const DEFAULT_CHECK_NAME = 'CTEM';

/** GitHub owner/login — no dots, so `github.com/foo` cannot sneak in as a repo. */
const OWNER_PART = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO_PART = /^[A-Za-z0-9._-]{1,100}$/;
const FULL_SHA = /^[0-9a-f]{40}$/i;

export interface GithubChecksContext {
  owner: string;
  repo: string;
  sha: string;
  checkName: string;
  detailsUrl?: string;
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

function validOwner(value: string): boolean {
  return OWNER_PART.test(value);
}

function validRepo(value: string): boolean {
  return REPO_PART.test(value) && value !== '.' && value !== '..';
}

function parseRepository(
  repository: string | undefined,
  owner: string | undefined,
  repo: string | undefined,
): { owner: string; repo: string } | null {
  if (repository) {
    if (looksLikeUrl(repository)) return null;
    const parts = repository.split('/');
    if (parts.length !== 2) return null;
    const [o, r] = parts;
    if (!o || !r || !validOwner(o) || !validRepo(r)) return null;
    return { owner: o, repo: r };
  }
  if (owner && repo) {
    if (looksLikeUrl(owner) || looksLikeUrl(repo)) return null;
    if (!validOwner(owner) || !validRepo(repo)) return null;
    return { owner, repo };
  }
  return null;
}

function parseSha(sha: string | undefined): string | null {
  if (!sha || !FULL_SHA.test(sha)) return null;
  return sha.toLowerCase();
}

function sanitizeCheckName(raw: string | undefined): string {
  const name = (raw ?? DEFAULT_CHECK_NAME).replace(/[\r\n\0]/g, ' ').trim();
  if (!name) return DEFAULT_CHECK_NAME;
  return name.slice(0, 100);
}

/**
 * `detailsUrl` must be a CTEM URL: HTTPS (or http://localhost for local), same
 * origin as platform `CTEM_PUBLIC_URL`, path `/v1/scans/:id` or `/scans/:id`.
 * Tenant-arbitrary hosts are omitted (not a scan failure).
 */
export function allowlistedCtemDetailsUrl(raw: string | undefined, scanId: string): string | undefined {
  const originRaw = process.env.CTEM_PUBLIC_URL?.trim();
  if (!originRaw) return undefined;

  let origin: URL;
  try {
    origin = new URL(originRaw);
  } catch {
    return undefined;
  }

  const candidateRaw = raw?.trim() || `${origin.origin.replace(/\/$/, '')}/v1/scans/${scanId}`;
  let candidate: URL;
  try {
    candidate = new URL(candidateRaw);
  } catch {
    return undefined;
  }

  const originHttpLocal =
    origin.protocol === 'http:' && (origin.hostname === 'localhost' || origin.hostname === '127.0.0.1');
  if (candidate.protocol !== 'https:' && !(originHttpLocal && candidate.protocol === 'http:')) {
    return undefined;
  }
  if (candidate.username || candidate.password) return undefined;
  if (candidate.hostname.toLowerCase() !== origin.hostname.toLowerCase()) return undefined;
  const originPort = origin.port || (origin.protocol === 'https:' ? '443' : '80');
  const candidatePort = candidate.port || (candidate.protocol === 'https:' ? '443' : '80');
  if (originPort !== candidatePort) return undefined;

  const path = candidate.pathname.replace(/\/$/, '') || '/';
  const allowed = [`/v1/scans/${scanId}`, `/scans/${scanId}`];
  if (!allowed.includes(path)) return undefined;
  return `${candidate.protocol}//${candidate.host}${path}`;
}

export function parseGithubChecksContext(options: unknown, scanId: string): GithubChecksContext | null {
  const opts = asRecord(options);
  const github = asRecord(opts.github);
  // Tenant endpoint keys (baseUrl, githubHost, …) are ignored — they must
  // never become the API host.

  const parsedRepo = parseRepository(
    stringField(github.repository) ?? stringField(opts.repository),
    stringField(github.owner) ?? stringField(opts.owner),
    stringField(github.repo) ?? stringField(opts.repo),
  );
  const sha = parseSha(stringField(github.sha) ?? stringField(opts.sha));
  if (!parsedRepo || !sha) return null;

  const checkName = sanitizeCheckName(stringField(github.checkName) ?? stringField(opts.checkName));
  const detailsUrl = allowlistedCtemDetailsUrl(
    stringField(github.detailsUrl) ?? stringField(opts.detailsUrl),
    scanId,
  );

  return {
    owner: parsedRepo.owner,
    repo: parsedRepo.repo,
    sha,
    checkName,
    ...(detailsUrl ? { detailsUrl } : {}),
  };
}

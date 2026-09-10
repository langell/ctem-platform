/**
 * GitHub Checks credentials. Same class as GHCR: platform-operated `env:GITHUB_*`
 * only. A missing or unusable pointer must not call api.github.com.
 *
 * Prefer the scan/asset integration `credentialRef` when it is an allowlisted
 * `env:GITHUB_*` name and the pointed token is usable. Otherwise the platform
 * default `env:GITHUB_TOKEN` is used for Checks only (still `GITHUB_*`).
 * Non-GITHUB refs (GITLAB_*, AWS_*, DATABASE_URL) are skipped — never read.
 */

const GITHUB_ENV_NAME = /^GITHUB_[A-Z0-9_]+$/;

/** Platform default for Checks when no scan/asset integration GITHUB_* ref exists. */
export const CHECKS_DEFAULT_CREDENTIAL_REF = 'env:GITHUB_TOKEN';

export class GithubChecksCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GithubChecksCredentialError';
  }
}

export function isGithubEnvRef(ref: string | null | undefined): boolean {
  if (!ref) return false;
  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);
  return scheme === 'env' && Boolean(key) && GITHUB_ENV_NAME.test(key);
}

function envKeyFromRef(ref: string): string {
  return ref.slice(ref.indexOf(':') + 1);
}

/**
 * Read an allowlisted `env:GITHUB_*` pointer. Does not read non-GITHUB names
 * (DATABASE_URL, AWS_*, GITLAB_*). Empty/missing values fail closed.
 */
export function requireGithubToken(credentialRef: string): string {
  if (!isGithubEnvRef(credentialRef)) {
    throw new GithubChecksCredentialError(
      `credentialRef '${credentialRef}' is not an env:GITHUB_* pointer — GitHub Checks only accept platform-operated GITHUB_* names`,
    );
  }
  const key = envKeyFromRef(credentialRef);
  const token = process.env[key];
  if (!token || !token.trim()) {
    throw new GithubChecksCredentialError(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to publish Checks without usable GITHUB_* credentials`,
    );
  }
  return token.trim();
}

export type ChecksTokenPick =
  | { ok: true; token: string; ref: string }
  | { ok: false; reason: string };

/**
 * Prefer the first usable scan/asset `env:GITHUB_*` ref. If none, the platform
 * default `env:GITHUB_TOKEN`. A present-but-unusable GITHUB_* ref fails closed
 * (no fallback to a different secret).
 */
export function resolveChecksGithubToken(credentialRefs: Array<string | null | undefined>): ChecksTokenPick {
  for (const ref of credentialRefs) {
    if (!ref || !isGithubEnvRef(ref)) continue;
    try {
      return { ok: true, token: requireGithubToken(ref), ref };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, reason: message };
    }
  }

  try {
    return {
      ok: true,
      token: requireGithubToken(CHECKS_DEFAULT_CREDENTIAL_REF),
      ref: CHECKS_DEFAULT_CREDENTIAL_REF,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: message };
  }
}

/**
 * GitLab Commit Status credentials. Same class as GitLab discovery / SCA clone:
 * platform-operated `env:GITLAB_*` only. A missing or unusable pointer must
 * not call the GitLab API. No GitLab CLI shell-out.
 *
 * Prefer the scan/asset integration `credentialRef` when it is an allowlisted
 * `env:GITLAB_*` name and the pointed token is usable. Otherwise the platform
 * default `env:GITLAB_TOKEN` is used for statuses only (still `GITLAB_*`).
 * Non-GITLAB refs (GITHUB_*, AWS_*, DATABASE_URL) are skipped — never read.
 */

const GITLAB_ENV_NAME = /^GITLAB_[A-Z0-9_]+$/;

/** Platform default for statuses when no scan/asset integration GITLAB_* ref exists. */
export const STATUSES_DEFAULT_CREDENTIAL_REF = 'env:GITLAB_TOKEN';

export class GitlabStatusesCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GitlabStatusesCredentialError';
  }
}

export function isGitlabEnvRef(ref: string | null | undefined): boolean {
  if (!ref) return false;
  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);
  return scheme === 'env' && Boolean(key) && GITLAB_ENV_NAME.test(key);
}

function envKeyFromRef(ref: string): string {
  return ref.slice(ref.indexOf(':') + 1);
}

/**
 * Read an allowlisted `env:GITLAB_*` pointer. Does not read non-GITLAB names
 * (DATABASE_URL, AWS_*, GITHUB_*). Empty/missing values fail closed.
 */
export function requireGitlabToken(credentialRef: string): string {
  if (!isGitlabEnvRef(credentialRef)) {
    throw new GitlabStatusesCredentialError(
      `credentialRef '${credentialRef}' is not an env:GITLAB_* pointer — GitLab Commit Statuses only accept platform-operated GITLAB_* names`,
    );
  }
  const key = envKeyFromRef(credentialRef);
  const token = process.env[key];
  if (!token || !token.trim()) {
    throw new GitlabStatusesCredentialError(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to publish Commit Statuses without usable GITLAB_* credentials`,
    );
  }
  return token.trim();
}

export type GitlabTokenPick =
  | { ok: true; token: string; ref: string }
  | { ok: false; reason: string };

/**
 * Prefer the first usable scan/asset `env:GITLAB_*` ref. If none, the platform
 * default `env:GITLAB_TOKEN`. A present-but-unusable GITLAB_* ref fails closed
 * (no fallback to a different secret).
 */
export function resolveStatusesGitlabToken(credentialRefs: Array<string | null | undefined>): GitlabTokenPick {
  for (const ref of credentialRefs) {
    if (!ref || !isGitlabEnvRef(ref)) continue;
    try {
      return { ok: true, token: requireGitlabToken(ref), ref };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, reason: message };
    }
  }

  try {
    return {
      ok: true,
      token: requireGitlabToken(STATUSES_DEFAULT_CREDENTIAL_REF),
      ref: STATUSES_DEFAULT_CREDENTIAL_REF,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: message };
  }
}

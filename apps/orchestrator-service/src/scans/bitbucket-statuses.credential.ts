/**
 * Bitbucket Cloud build-status credentials. Same class as Bitbucket discovery
 * / SCA clone: platform-operated `env:BITBUCKET_*` only. A missing or unusable
 * pointer must not call the Bitbucket API. No Bitbucket CLI shell-out.
 *
 * Prefer the scan/asset integration `credentialRef` when it is an allowlisted
 * `env:BITBUCKET_*` name and the pointed token is usable. Otherwise the
 * platform default `env:BITBUCKET_TOKEN` is used for statuses only (still
 * `BITBUCKET_*`). Non-BITBUCKET refs (GITHUB_*, GITLAB_*, AWS_*, DATABASE_URL)
 * are skipped — never read.
 */

const BITBUCKET_ENV_NAME = /^BITBUCKET_[A-Z0-9_]+$/;

/** Platform default for statuses when no scan/asset integration BITBUCKET_* ref exists. */
export const STATUSES_DEFAULT_CREDENTIAL_REF = 'env:BITBUCKET_TOKEN';

export class BitbucketStatusesCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BitbucketStatusesCredentialError';
  }
}

export function isBitbucketEnvRef(ref: string | null | undefined): boolean {
  if (!ref) return false;
  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);
  return scheme === 'env' && Boolean(key) && BITBUCKET_ENV_NAME.test(key);
}

function envKeyFromRef(ref: string): string {
  return ref.slice(ref.indexOf(':') + 1);
}

/**
 * Read an allowlisted `env:BITBUCKET_*` pointer. Does not read non-BITBUCKET
 * names (DATABASE_URL, AWS_*, GITHUB_*, GITLAB_*). Empty/missing values fail closed.
 */
export function requireBitbucketToken(credentialRef: string): string {
  if (!isBitbucketEnvRef(credentialRef)) {
    throw new BitbucketStatusesCredentialError(
      `credentialRef '${credentialRef}' is not an env:BITBUCKET_* pointer — Bitbucket build statuses only accept platform-operated BITBUCKET_* names`,
    );
  }
  const key = envKeyFromRef(credentialRef);
  const token = process.env[key];
  if (!token || !token.trim()) {
    throw new BitbucketStatusesCredentialError(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to publish build statuses without usable BITBUCKET_* credentials`,
    );
  }
  return token.trim();
}

export type BitbucketTokenPick =
  { ok: true; token: string; ref: string } | { ok: false; reason: string };

/**
 * Prefer the first usable scan/asset `env:BITBUCKET_*` ref. If none, the
 * platform default `env:BITBUCKET_TOKEN`. A present-but-unusable BITBUCKET_*
 * ref fails closed (no fallback to a different secret).
 */
export function resolveStatusesBitbucketToken(
  credentialRefs: Array<string | null | undefined>,
): BitbucketTokenPick {
  for (const ref of credentialRefs) {
    if (!ref || !isBitbucketEnvRef(ref)) continue;
    try {
      return { ok: true, token: requireBitbucketToken(ref), ref };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, reason: message };
    }
  }

  try {
    return {
      ok: true,
      token: requireBitbucketToken(STATUSES_DEFAULT_CREDENTIAL_REF),
      ref: STATUSES_DEFAULT_CREDENTIAL_REF,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: message };
  }
}

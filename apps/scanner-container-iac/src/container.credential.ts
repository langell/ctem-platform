/**
 * Same allowlist as GHCR discovery (`apps/asset-service` credentials).
 * Platform-operated `env:GITHUB_*` only. A missing or unusable pointer must
 * fail a private pull — never empty-succeed.
 */

const ENV_ALLOWLIST = /^(GITHUB|GITLAB|AWS|GCP|AZURE)_[A-Z0-9_]+$/;
const GITHUB_ENV_NAME = /^GITHUB_[A-Z0-9_]+$/;

export class ContainerCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContainerCredentialError';
  }
}

function resolveCredential(ref: string | null): string | undefined {
  if (!ref) return undefined;

  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);

  if (scheme === 'env') {
    if (!key || !ENV_ALLOWLIST.test(key)) {
      throw new ContainerCredentialError(
        `credentialRef 'env:${key || '<empty>'}' is not allowlisted — env: is platform-operated and only GITHUB_* / GITLAB_* / AWS_* / GCP_* / AZURE_* names are permitted`,
      );
    }
    return process.env[key] || undefined;
  }

  throw new ContainerCredentialError(
    `Unsupported credentialRef scheme '${scheme}' — only 'env:<VAR>' is implemented`,
  );
}

/**
 * Private GHCR pulls have no unauthenticated path. The integration pointer
 * must be `env:GITHUB_*` (same as discovery — not `GHCR_*`), and the pointed
 * token must be usable.
 */
export function requireGithubToken(credentialRef: string | null): string {
  if (!credentialRef) {
    throw new ContainerCredentialError(
      'Private GHCR pull requires a usable credentialRef (env:GITHUB_*) — refusing unauthenticated pull',
    );
  }

  const sep = credentialRef.indexOf(':');
  const scheme = sep === -1 ? credentialRef : credentialRef.slice(0, sep);
  const key = sep === -1 ? '' : credentialRef.slice(sep + 1);
  if (scheme !== 'env' || !key || !GITHUB_ENV_NAME.test(key)) {
    resolveCredential(credentialRef);
    throw new ContainerCredentialError(
      `credentialRef '${credentialRef}' is not an env:GITHUB_* pointer — GHCR pulls only accept platform-operated GITHUB_* names`,
    );
  }

  const token = resolveCredential(credentialRef);
  if (!token || !token.trim()) {
    throw new ContainerCredentialError(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to pull without usable GITHUB_* credentials`,
    );
  }

  return token.trim();
}

/** Public images may omit credentials; a set-but-unusable GITHUB_* pointer still fails. */
export function optionalGithubToken(credentialRef: string | null): string | undefined {
  if (!credentialRef) return undefined;
  return requireGithubToken(credentialRef);
}

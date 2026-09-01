/**
 * Resolves an Integration.credentialRef into a secret. The ref is a pointer,
 * never the credential itself. Schemes:
 *
 *   env:<VAR>  — platform-operated only. Reads a process environment variable
 *                whose name is allowlisted (`GITHUB_*`, `GITLAB_*`, or `AWS_*`).
 *                This is not a tenant-writable secret store: a tenant-supplied
 *                credentialRef cannot read DATABASE_URL, PATH,
 *                INTERNAL_TOKEN_SECRET, or other replica secrets. Every
 *                integration that points at the same env name shares that
 *                replica-global value until a real per-tenant store (vault:,
 *                aws-sm:) exists.
 *
 * Connectors stay oblivious to the scheme.
 */

/** Platform-controlled names only — not an open read of process.env. */
const ENV_ALLOWLIST = /^(GITHUB|GITLAB|AWS)_[A-Z0-9_]+$/;

export function resolveCredential(ref: string | null): string | undefined {
  if (!ref) return undefined;

  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);

  if (scheme === 'env') {
    if (!key || !ENV_ALLOWLIST.test(key)) {
      throw new Error(
        `credentialRef 'env:${key || '<empty>'}' is not allowlisted — env: is platform-operated and only GITHUB_* / GITLAB_* / AWS_* names are permitted`,
      );
    }
    return process.env[key] || undefined;
  }

  throw new Error(
    `Unsupported credentialRef scheme '${scheme}' — only 'env:<VAR>' is implemented`,
  );
}

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

const AWS_ENV_NAME = /^AWS_[A-Z0-9_]+$/;

/**
 * AWS discovery has no unauthenticated public path. The integration pointer
 * must be `env:AWS_*`, and the platform-operated signing pair
 * `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` must both be usable.
 */
export function requireAwsCredentials(credentialRef: string | null): AwsCredentials {
  if (!credentialRef) {
    throw new Error(
      'AWS discovery requires a usable credentialRef (env:AWS_*) — refusing unauthenticated listing',
    );
  }

  const sep = credentialRef.indexOf(':');
  const scheme = sep === -1 ? credentialRef : credentialRef.slice(0, sep);
  const key = sep === -1 ? '' : credentialRef.slice(sep + 1);
  if (scheme !== 'env' || !key || !AWS_ENV_NAME.test(key)) {
    // Non-allowlisted names throw here without reading the secret (DATABASE_URL).
    // Allowlisted-but-not-AWS names (GITHUB_*) are refused after that check.
    resolveCredential(credentialRef);
    throw new Error(
      `credentialRef '${credentialRef}' is not an env:AWS_* pointer — AWS discovery only accepts platform-operated AWS_* names`,
    );
  }

  const pointed = resolveCredential(credentialRef);
  if (!pointed) {
    throw new Error(
      `credentialRef '${credentialRef}' is set but cannot be used — refusing to list without usable AWS_* credentials`,
    );
  }

  const accessKeyId = resolveCredential('env:AWS_ACCESS_KEY_ID');
  const secretAccessKey = resolveCredential('env:AWS_SECRET_ACCESS_KEY');
  if (!accessKeyId || !secretAccessKey) {
    throw new Error(
      'AWS discovery fails closed without usable AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY',
    );
  }

  const sessionToken = resolveCredential('env:AWS_SESSION_TOKEN');
  return { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) };
}

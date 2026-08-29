/**
 * Resolves an Integration.credentialRef into a secret. The ref is a pointer,
 * never the credential itself. Schemes:
 *
 *   env:<VAR>  — platform-operated only. Reads a process environment variable
 *                whose name is allowlisted (`GITHUB_*` or `GITLAB_*`). This is
 *                not a tenant-writable secret store: a tenant-supplied
 *                credentialRef cannot read DATABASE_URL, PATH,
 *                INTERNAL_TOKEN_SECRET, or other replica secrets. Every
 *                integration that points at the same env name shares that
 *                replica-global value until a real per-tenant store (vault:,
 *                aws-sm:) exists.
 *
 * Connectors stay oblivious to the scheme.
 */

/** Platform-controlled names only — not an open read of process.env. */
const ENV_ALLOWLIST = /^(GITHUB|GITLAB)_[A-Z0-9_]+$/;

export function resolveCredential(ref: string | null): string | undefined {
  if (!ref) return undefined;

  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);

  if (scheme === 'env') {
    if (!key || !ENV_ALLOWLIST.test(key)) {
      throw new Error(
        `credentialRef 'env:${key || '<empty>'}' is not allowlisted — env: is platform-operated and only GITHUB_* / GITLAB_* names are permitted`,
      );
    }
    return process.env[key] || undefined;
  }

  throw new Error(
    `Unsupported credentialRef scheme '${scheme}' — only 'env:<VAR>' is implemented`,
  );
}

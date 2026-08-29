/**
 * Same allowlist as `apps/asset-service/src/connectors/credentials.ts`.
 * Env refs are platform-operated: only `GITHUB_*` names, never a tenant-writable
 * read of replica secrets. A set-but-unusable credentialRef must fail the job.
 */

const ENV_ALLOWLIST = /^GITHUB_[A-Z0-9_]+$/;

export function resolveGithubCredential(ref: string | null): string | undefined {
  if (!ref) return undefined;

  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);

  if (scheme === 'env') {
    if (!key || !ENV_ALLOWLIST.test(key)) {
      throw new Error(
        `credentialRef 'env:${key || '<empty>'}' is not allowlisted — env: is platform-operated and only GITHUB_* names are permitted`,
      );
    }
    return process.env[key] || undefined;
  }

  throw new Error(`Unsupported credentialRef scheme '${scheme}' — only 'env:<VAR>' is implemented`);
}

export function isPrivateTarget(target: Record<string, unknown>): boolean {
  if (target.private === true) return true;
  if (target.visibility === 'private') return true;
  return false;
}

/**
 * Resolves a Slack credentialRef into a secret. Same platform-operated `env:`
 * pattern as GITHUB_* / GITLAB_*: the ref is a pointer, never the credential
 * itself, and only `SLACK_*` names are readable.
 *
 * A tenant-supplied credentialRef cannot read DATABASE_URL, PATH,
 * INTERNAL_TOKEN_SECRET, GITHUB_TOKEN, or other replica secrets.
 */

/** Platform-controlled Slack names only — not an open read of process.env. */
const ENV_ALLOWLIST = /^SLACK_[A-Z0-9_]+$/;

export const PLATFORM_SLACK_CREDENTIAL_REF = 'env:SLACK_WEBHOOK_URL';

export function resolveSlackCredential(ref: string | null): string | undefined {
  if (!ref) return undefined;

  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);

  if (scheme === 'env') {
    if (!key || !ENV_ALLOWLIST.test(key)) {
      throw new Error(
        `credentialRef 'env:${key || '<empty>'}' is not allowlisted — env: is platform-operated and only SLACK_* names are permitted`,
      );
    }
    return process.env[key] || undefined;
  }

  throw new Error(
    `Unsupported credentialRef scheme '${scheme}' — only 'env:<VAR>' is implemented`,
  );
}

/**
 * Slack incoming-webhook URL. Fail closed when the platform ref is missing
 * or empty — there is no unauthenticated public path.
 */
export function requireSlackWebhookCredential(
  ref: string = PLATFORM_SLACK_CREDENTIAL_REF,
): string {
  const value = resolveSlackCredential(ref);
  if (!value) {
    throw new Error(
      `credentialRef '${ref}' is set but cannot be used — Slack notify fails closed without a usable SLACK_* secret`,
    );
  }
  return value;
}

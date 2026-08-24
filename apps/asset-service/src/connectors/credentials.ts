/**
 * Resolves an Integration.credentialRef into a secret. The ref is a pointer,
 * never the credential itself. Schemes:
 *
 *   env:<VAR>  — read from the service's environment. Dev/CI convenience and
 *                the platform-operated integrations path.
 *
 * A real secret-store scheme (vault:, aws-sm:) slots in here when one exists;
 * connectors stay oblivious.
 */
export function resolveCredential(ref: string | null): string | undefined {
  if (!ref) return undefined;

  const sep = ref.indexOf(':');
  const scheme = sep === -1 ? ref : ref.slice(0, sep);
  const key = sep === -1 ? '' : ref.slice(sep + 1);

  if (scheme === 'env' && key) return process.env[key] || undefined;

  throw new Error(
    `Unsupported credentialRef scheme '${scheme}' — only 'env:<VAR>' is implemented`,
  );
}

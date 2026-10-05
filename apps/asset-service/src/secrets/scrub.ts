const TOKEN_LIKE = /(?:ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]+|Bearer\s+\S+/g;

/** Remove a known secret and token-shaped substrings from text that may be stored or logged. */
export function scrubText(raw: string, secret?: string): string {
  let message = raw;
  if (secret && secret.length > 0) {
    message = message.split(secret).join('[redacted]');
  }
  return message.replace(TOKEN_LIKE, '[redacted]');
}

/** Fixed sync/API text. Never returns the plaintext credential. */
export function scrubSyncError(err: unknown, secret?: string): string {
  const raw = err instanceof Error ? err.message : 'Discovery sync failed';
  return scrubText(raw, secret);
}

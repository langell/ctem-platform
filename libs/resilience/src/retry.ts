/** Statuses that may be retried on internal HTTP. 4xx is never retried. */
export const RETRYABLE_HTTP_STATUSES = [502, 503, 504] as const;

export type RetryableHttpStatus = (typeof RETRYABLE_HTTP_STATUSES)[number];

export function isRetryableHttpStatus(status: number): status is RetryableHttpStatus {
  return (RETRYABLE_HTTP_STATUSES as readonly number[]).includes(status);
}

/**
 * Timeouts from `AbortSignal.timeout` (DOMException `TimeoutError`) and
 * aborted signals. Used to decide retry + 504 mapping at the gateway edge.
 */
export function isTimeoutError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const name = 'name' in err ? String(err.name) : '';
  const code = 'code' in err ? String(err.code) : '';
  if (name === 'TimeoutError' || name === 'AbortError') return true;
  if (code === 'ABORT_ERR' || code === 'UND_ERR_CONNECT_TIMEOUT') return true;
  if ('cause' in err) return isTimeoutError((err as { cause?: unknown }).cause);
  return false;
}

/**
 * Failures that consume retry budget: timeouts and fetch/network transport
 * errors. HTTP 502–504 are classified from the status on a completed response,
 * not from this helper. Programming errors are not retryable.
 */
export function isRetryableError(err: unknown): boolean {
  if (isTimeoutError(err)) return true;
  if (err instanceof TypeError) {
    const msg = err.message ?? '';
    if (/fetch|network|ECONNREFUSED|ENOTFOUND|ECONNRESET|ETIMEDOUT|EAI_AGAIN/i.test(msg)) {
      return true;
    }
  }
  if (err && typeof err === 'object' && 'cause' in err) {
    const cause = (err as { cause?: unknown }).cause;
    if (cause && typeof cause === 'object' && 'code' in cause) {
      const code = String((cause as { code: unknown }).code);
      if (['ECONNREFUSED', 'ENOTFOUND', 'ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN'].includes(code)) {
        return true;
      }
    }
    if (isRetryableError(cause)) return true;
  }
  return false;
}

/**
 * Full jitter: `floor(random() * (baseDelayMs * 2^(attempt-1) + 1))`.
 * `attempt` is 1-based (the attempt that just failed).
 */
export function retryDelayMs(
  attempt: number,
  baseDelayMs: number,
  random: () => number = Math.random,
): number {
  const exp = 2 ** Math.max(0, attempt - 1);
  const cap = baseDelayMs * exp;
  return Math.floor(random() * (cap + 1));
}

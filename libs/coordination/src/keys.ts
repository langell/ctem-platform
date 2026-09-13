/** Redis keys for control-plane interval leaders. Distinct so each scheduler elects independently. */
export const SCAN_SCHEDULE_LEASE_KEY = 'ctem:leader:scan-schedule';
export const DISCOVERY_SCHEDULE_LEASE_KEY = 'ctem:leader:discovery-schedule';

/**
 * Per-IP gateway token bucket. Shared across api-gateway replicas so a second
 * replica cannot bypass the 600/min budget. Keyed by `req.ip` only — never org,
 * body, query, or JWT.
 */
export const GATEWAY_RATE_LIMIT_KEY_PREFIX = 'ctem:ratelimit:gw:';

export function gatewayRateLimitRedisKey(ip: string): string {
  return `${GATEWAY_RATE_LIMIT_KEY_PREFIX}${ip}`;
}

/** How long a holder may disappear before another replica can take over. */
export const DEFAULT_LEASE_TTL_MS = 15_000;

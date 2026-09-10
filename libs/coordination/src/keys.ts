/** Redis keys for control-plane interval leaders. Distinct so each scheduler elects independently. */
export const SCAN_SCHEDULE_LEASE_KEY = 'ctem:leader:scan-schedule';
export const DISCOVERY_SCHEDULE_LEASE_KEY = 'ctem:leader:discovery-schedule';

/** How long a holder may disappear before another replica can take over. */
export const DEFAULT_LEASE_TTL_MS = 15_000;

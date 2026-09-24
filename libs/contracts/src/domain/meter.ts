import { z } from 'zod';
import { OrgId } from '../common';
import { ScannerType } from './scan';

/** Primary billable event. One accepted scan kick — not a job, finding, or pull. */
export const SCAN_KICK_EVENT = 'scan.kick' as const;

/** Flat per kick. `api` is reserved for a future distinct trigger; v0 records the orchestrator trigger. */
export const ScanKickSource = z.enum(['manual', 'api', 'webhook', 'ci', 'schedule']);
export type ScanKickSource = z.infer<typeof ScanKickSource>;

/**
 * Durable meter record for one accepted kick.
 * `scannerTypes` is an analytics dimension, not a price multiplier.
 */
export const ScanKickMeterRecord = z.object({
  eventId: z.string().uuid(),
  orgId: OrgId,
  scanId: z.string().uuid(),
  source: ScanKickSource,
  scannerTypes: z.array(ScannerType).optional(),
  occurredAt: z.coerce.date(),
});
export type ScanKickMeterRecord = z.infer<typeof ScanKickMeterRecord>;

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

/** Page size when `limit` is omitted. Values above the max are capped, not rejected. */
export const SCAN_KICK_LIST_DEFAULT_LIMIT = 50;
export const SCAN_KICK_LIST_MAX_LIMIT = 200;

/**
 * Applied only when neither `from` nor `to` is set.
 * 30 × 24h, not a calendar month. Lower bound is inclusive; there is no upper bound.
 */
export const SCAN_KICK_DEFAULT_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * OpenAPI description for `GET /v1/meters/scan-kicks` and the internal twin.
 * `from` is inclusive (`occurredAt >= from`). `to` is exclusive (`occurredAt < to`).
 */
export const SCAN_KICK_METER_READ_DESCRIPTION =
  'Lists durable scan.kick rows for the authenticated organization. ' +
  'from is an inclusive lower bound on occurredAt (ISO-8601, occurredAt >= from). ' +
  'to is an exclusive upper bound (ISO-8601, occurredAt < to). ' +
  'When neither from nor to is set, the window defaults to the last 30 days ' +
  '(occurredAt >= now - 30x24h) with no upper bound. ' +
  'Setting either bound disables that default. ' +
  'source is one of manual, api, webhook, ci, schedule. ' +
  'limit defaults to 50 and is capped at 200. ' +
  'cursor is an opaque keyset on (occurredAt, eventId) descending; nextCursor continues it. ' +
  'total is the count of rows matching the filters, ignoring cursor and limit. ' +
  'The organization is taken from the token only; a query orgId is ignored. ' +
  'The response has no price, currency, or remaining-credits fields.';

const ISO_8601 = /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))?$/;

function firstQueryValue(value: unknown): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  if (raw === undefined || raw === null) return undefined;
  const text = String(raw).trim();
  return text.length ? text : undefined;
}

const optionalQueryString = z.preprocess(firstQueryValue, z.string().optional());

/**
 * Filters for the meter read. `orgId` is not a field — callers cannot select a tenant.
 * Unknown keys (including `orgId`) are stripped.
 */
export const ListScanKicksQuery = z
  .object({
    from: optionalQueryString.describe(
      'Inclusive lower bound on occurredAt (ISO-8601). occurredAt >= from.',
    ),
    to: optionalQueryString.describe(
      'Exclusive upper bound on occurredAt (ISO-8601). occurredAt < to.',
    ),
    source: optionalQueryString.describe('manual | api | webhook | ci | schedule'),
    cursor: optionalQueryString.describe(
      'Opaque keyset cursor on (occurredAt, eventId) descending.',
    ),
    limit: optionalQueryString.describe('Page size. Default 50. Capped at 200.'),
  })
  .transform((query, ctx) => {
    let failed = false;
    const issue = (path: string, message: string) => {
      failed = true;
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: [path], message });
    };

    const instant = (value: string | undefined, path: 'from' | 'to'): Date | undefined => {
      if (value === undefined) return undefined;
      if (!ISO_8601.test(value)) {
        issue(path, `${path} must be an ISO-8601 date or date-time`);
        return undefined;
      }
      const date = value.length === 10 ? new Date(`${value}T00:00:00.000Z`) : new Date(value);
      if (Number.isNaN(date.getTime())) {
        issue(path, `${path} must be an ISO-8601 date or date-time`);
        return undefined;
      }
      return date;
    };

    const from = instant(query.from, 'from');
    const to = instant(query.to, 'to');

    let source: ScanKickSource | undefined;
    if (query.source !== undefined) {
      const parsed = ScanKickSource.safeParse(query.source);
      if (!parsed.success) issue('source', 'source must be manual, api, webhook, ci, or schedule');
      else source = parsed.data;
    }

    let limit = SCAN_KICK_LIST_DEFAULT_LIMIT;
    if (query.limit !== undefined) {
      if (!/^[1-9]\d*$/.test(query.limit)) issue('limit', 'limit must be a positive integer');
      else limit = Math.min(Number(query.limit), SCAN_KICK_LIST_MAX_LIMIT);
    }

    if (failed) return z.NEVER;
    return {
      ...(from ? { from } : {}),
      ...(to ? { to } : {}),
      ...(source ? { source } : {}),
      ...(query.cursor ? { cursor: query.cursor } : {}),
      limit,
    };
  });
export type ListScanKicksQuery = z.infer<typeof ListScanKicksQuery>;

/**
 * Read envelope. `nextCursor` is the opaque continuation of `(occurredAt, eventId)` desc.
 * Strict so price, currency, and remaining-credits cannot sneak in.
 */
export const ScanKickMeterUsage = z
  .object({
    event: z.literal(SCAN_KICK_EVENT),
    total: z.number().int().nonnegative(),
    items: z.array(ScanKickMeterRecord),
    nextCursor: z.string().nullable(),
  })
  .strict();
export type ScanKickMeterUsage = z.infer<typeof ScanKickMeterUsage>;

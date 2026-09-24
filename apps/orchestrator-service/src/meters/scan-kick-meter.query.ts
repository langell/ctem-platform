import { BadRequestException } from '@nestjs/common';
import type { Prisma } from '@ctem/db';
import {
  SCAN_KICK_DEFAULT_WINDOW_MS,
  type ListScanKicksQuery,
  type ScanKickSource,
} from '@ctem/contracts';
import { z } from 'zod';

const ScanKickCursor = z.object({
  occurredAt: z.string().datetime({ offset: true }),
  eventId: z.string().uuid(),
});

export interface ScanKickCursorPoint {
  occurredAt: Date;
  eventId: string;
}

export interface ScanKickBounds {
  from?: Date;
  to?: Date;
  source?: ScanKickSource;
  cursor?: ScanKickCursorPoint;
  limit: number;
}

/** Opaque cursor. Callers cannot construct a useful one without `nextCursor`. */
export function encodeScanKickCursor(row: { occurredAt: Date; eventId: string }): string {
  return Buffer.from(
    JSON.stringify({ occurredAt: row.occurredAt.toISOString(), eventId: row.eventId }),
    'utf8',
  ).toString('base64url');
}

export function decodeScanKickCursor(cursor: string): ScanKickCursorPoint {
  if (cursor.length > 512) throw new BadRequestException('Invalid scan kick cursor');
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
  } catch {
    throw new BadRequestException('Invalid scan kick cursor');
  }
  const result = ScanKickCursor.safeParse(parsed);
  if (!result.success) throw new BadRequestException('Invalid scan kick cursor');
  return { occurredAt: new Date(result.data.occurredAt), eventId: result.data.eventId };
}

/**
 * `from` inclusive, `to` exclusive. Neither bound set → last 30x24h, no upper bound.
 * Either bound set → use only what the caller sent (the 30d default does not apply).
 */
export function resolveScanKickBounds(query: ListScanKicksQuery, now: Date): ScanKickBounds {
  const defaulted = query.from === undefined && query.to === undefined;
  return {
    from: defaulted ? new Date(now.getTime() - SCAN_KICK_DEFAULT_WINDOW_MS) : query.from,
    to: query.to,
    source: query.source,
    cursor: query.cursor ? decodeScanKickCursor(query.cursor) : undefined,
    limit: query.limit,
  };
}

/** Filter for `total`. Cursor and limit do not change the count. */
export function scanKickCountWhere(bounds: ScanKickBounds): Prisma.ScanKickWhereInput {
  const where: Prisma.ScanKickWhereInput = {};
  if (bounds.from || bounds.to) {
    where.occurredAt = {
      ...(bounds.from ? { gte: bounds.from } : {}),
      ...(bounds.to ? { lt: bounds.to } : {}),
    };
  }
  if (bounds.source) where.source = bounds.source;
  return where;
}

/**
 * Keyset page on `(occurredAt, eventId)` descending. The cursor row is not
 * looked up, so a cursor that names another tenant's event cannot 500.
 */
export function scanKickPageWhere(bounds: ScanKickBounds): Prisma.ScanKickWhereInput {
  const base = scanKickCountWhere(bounds);
  if (!bounds.cursor) return base;
  return {
    AND: [
      base,
      {
        OR: [
          { occurredAt: { lt: bounds.cursor.occurredAt } },
          {
            occurredAt: bounds.cursor.occurredAt,
            eventId: { lt: bounds.cursor.eventId },
          },
        ],
      },
    ],
  };
}

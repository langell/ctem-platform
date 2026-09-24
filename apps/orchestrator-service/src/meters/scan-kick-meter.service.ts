import { Injectable } from '@nestjs/common';
import {
  SCAN_KICK_EVENT,
  ScanKickMeterRecord,
  ScanKickMeterUsage,
  type ListScanKicksQuery,
} from '@ctem/contracts';
import { PrismaService } from '@ctem/db';
import {
  encodeScanKickCursor,
  resolveScanKickBounds,
  scanKickCountWhere,
  scanKickPageWhere,
} from './scan-kick-meter.query';

/**
 * Read-only. Emit, idempotency, and the scan insert stay in the dispatcher.
 * Isolation is `withOrg` plus RLS — this query does not add its own `orgId` predicate.
 */
@Injectable()
export class ScanKickMeterService {
  constructor(private readonly prisma: PrismaService) {}

  async list(
    orgId: string,
    query: ListScanKicksQuery,
    now = new Date(),
  ): Promise<ScanKickMeterUsage> {
    const bounds = resolveScanKickBounds(query, now);
    // An empty half-open window matches nothing. Skip the database; there is nothing to leak.
    if (bounds.from && bounds.to && bounds.from.getTime() >= bounds.to.getTime()) {
      return emptyUsage();
    }

    return this.prisma.withOrg(orgId, async (tx) => {
      const total = await tx.scanKick.count({ where: scanKickCountWhere(bounds) });
      const rows = await tx.scanKick.findMany({
        where: scanKickPageWhere(bounds),
        orderBy: [{ occurredAt: 'desc' }, { eventId: 'desc' }],
        take: bounds.limit + 1,
        select: {
          eventId: true,
          orgId: true,
          scanId: true,
          source: true,
          scannerTypes: true,
          occurredAt: true,
        },
      });

      const hasMore = rows.length > bounds.limit;
      const page = hasMore ? rows.slice(0, bounds.limit) : rows;
      const last = page.at(-1);
      return ScanKickMeterUsage.parse({
        event: SCAN_KICK_EVENT,
        total,
        items: page.map((row) => ScanKickMeterRecord.parse(row)),
        nextCursor: hasMore && last ? encodeScanKickCursor(last) : null,
      });
    });
  }
}

function emptyUsage(): ScanKickMeterUsage {
  return { event: SCAN_KICK_EVENT, total: 0, items: [], nextCursor: null };
}

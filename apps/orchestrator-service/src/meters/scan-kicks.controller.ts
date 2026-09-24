import { Controller, Get, Query } from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { CurrentOrg, RequirePermissions } from '@ctem/auth';
import { ListScanKicksQuery, SCAN_KICK_METER_READ_DESCRIPTION } from '@ctem/contracts';
import { ZodQuery } from '@ctem/service-kit';
import { ScanKickMeterService } from './scan-kick-meter.service';

/**
 * Org-scoped read over `scan_kicks`. The org is the signed principal
 * (`@CurrentOrg`), never a query `orgId`. `withOrg` and RLS fail closed the
 * same way scan GET does: another tenant's rows are invisible, and a probe
 * does not 500.
 */
@ApiTags('meters')
@Controller('internal/meters/scan-kicks')
export class ScanKicksController {
  constructor(private readonly meters: ScanKickMeterService) {}

  @Get()
  @RequirePermissions('scan:read')
  @ApiOperation({
    summary: 'List scan.kick usage for the principal organization',
    description: SCAN_KICK_METER_READ_DESCRIPTION,
  })
  @ApiQuery({
    name: 'from',
    required: false,
    description: 'Inclusive lower bound on occurredAt (ISO-8601). occurredAt >= from.',
    schema: { type: 'string', format: 'date-time' },
  })
  @ApiQuery({
    name: 'to',
    required: false,
    description: 'Exclusive upper bound on occurredAt (ISO-8601). occurredAt < to.',
    schema: { type: 'string', format: 'date-time' },
  })
  @ApiQuery({
    name: 'source',
    required: false,
    enum: ['manual', 'api', 'webhook', 'ci', 'schedule'],
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    description: 'Page size. Default 50. Values above 200 are capped at 200.',
    schema: { type: 'integer', minimum: 1, maximum: 200, default: 50 },
  })
  @ApiQuery({
    name: 'cursor',
    required: false,
    description: 'Opaque keyset cursor on (occurredAt, eventId) descending.',
  })
  list(
    @CurrentOrg() orgId: string,
    @Query(new ZodQuery(ListScanKicksQuery)) query: ListScanKicksQuery,
  ) {
    return this.meters.list(orgId, query);
  }
}

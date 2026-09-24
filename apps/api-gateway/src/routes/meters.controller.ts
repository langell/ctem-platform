import { Controller, Get, Query, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { RequirePermissions } from '@ctem/auth';
import { SCAN_KICK_METER_READ_DESCRIPTION } from '@ctem/contracts';
import { ServiceProxy } from '../proxy/service-proxy';

const METER_QUERY_KEYS = ['from', 'to', 'source', 'limit', 'cursor'] as const;

/**
 * Read API for durable scan.kick usage. The org is the bearer token
 * (gateway auth principal). Query `orgId` is dropped before the forward.
 * This proxy does not emit a meter row.
 */
@ApiTags('meters')
@ApiBearerAuth()
@Controller('v1/meters')
export class MetersProxyController {
  constructor(private readonly proxy: ServiceProxy) {}

  @Get('scan-kicks')
  @RequirePermissions('scan:read')
  @ApiOperation({
    summary: 'List scan.kick usage for the token organization',
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
  list(@Req() req: never, @Query() query: Record<string, unknown>) {
    return this.proxy.forward('orchestrator', 'GET', '/internal/meters/scan-kicks', req, {
      query: scanKickMeterQuery(query),
    });
  }
}

/** Allow-list. `orgId` and any other query key never reach the orchestrator. */
export function scanKickMeterQuery(query: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of METER_QUERY_KEYS) {
    const value = query[key];
    const raw = Array.isArray(value) ? value[0] : value;
    if (typeof raw !== 'string') continue;
    const trimmed = raw.trim();
    if (trimmed) out[key] = trimmed;
  }
  return out;
}

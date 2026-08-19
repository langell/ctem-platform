import { Body, Controller, Get, Param, Patch, Query, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { RequirePermissions } from '@ctem/auth';
import type { ListFindingsQuery, TriageFindingRequest } from '@ctem/contracts';
import { ServiceProxy } from '../proxy/service-proxy';

@ApiTags('findings')
@ApiBearerAuth()
@Controller('v1/findings')
export class FindingsProxyController {
  constructor(private readonly proxy: ServiceProxy) {}

  @Get()
  @RequirePermissions('finding:read')
  list(@Req() req: never, @Query() query: ListFindingsQuery) {
    return this.proxy.forward('findings', 'GET', '/internal/findings', req, { query });
  }

  @Get(':id')
  @RequirePermissions('finding:read')
  get(@Req() req: never, @Param('id') id: string) {
    return this.proxy.forward('findings', 'GET', `/internal/findings/${id}`, req);
  }

  /** "Why is this a 91?" — the explanation is a first-class endpoint, not a tooltip. */
  @Get(':id/risk')
  @RequirePermissions('finding:read')
  risk(@Req() req: never, @Param('id') id: string) {
    return this.proxy.forward('risk', 'GET', `/internal/risk/findings/${id}`, req);
  }

  @Patch(':id/triage')
  @RequirePermissions('finding:triage')
  triage(@Req() req: never, @Param('id') id: string, @Body() body: TriageFindingRequest) {
    return this.proxy.forward('findings', 'PATCH', `/internal/findings/${id}/triage`, req, { body });
  }
}

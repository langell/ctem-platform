import { Body, Controller, Get, Param, Patch, Query } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CurrentOrg, CurrentUser, RequirePermissions } from '@ctem/auth';
import { ListFindingsQuery, TriageFindingRequest, type Principal } from '@ctem/contracts';
import { ZodBody, ZodQuery } from '@ctem/service-kit';
import { FindingsService } from './findings.service';

@ApiTags('findings')
@Controller('internal/findings')
export class FindingsController {
  constructor(private readonly findings: FindingsService) {}

  @Get()
  @RequirePermissions('finding:read')
  list(
    @CurrentOrg() orgId: string,
    @Query(new ZodQuery(ListFindingsQuery)) query: ListFindingsQuery,
  ) {
    return this.findings.list(orgId, query);
  }

  @Get(':id')
  @RequirePermissions('finding:read')
  get(@CurrentOrg() orgId: string, @Param('id') id: string) {
    return this.findings.get(orgId, id);
  }

  @Patch(':id/triage')
  @RequirePermissions('finding:triage')
  triage(
    @CurrentOrg() orgId: string,
    @CurrentUser() user: Principal,
    @Param('id') id: string,
    @Body(new ZodBody(TriageFindingRequest)) body: TriageFindingRequest,
  ) {
    return this.findings.triage(orgId, id, user.userId, body);
  }
}

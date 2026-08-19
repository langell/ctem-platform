import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CurrentOrg, RequirePermissions } from '@ctem/auth';
import { PrismaService } from '@ctem/db';
import { RiskScoringService } from './risk-scoring.service';
import { PolicyEngineService } from '../policy/policy-engine.service';

@ApiTags('risk')
@Controller('internal/risk')
export class RiskController {
  constructor(
    private readonly scoring: RiskScoringService,
    private readonly policy: PolicyEngineService,
    private readonly prisma: PrismaService,
  ) {}

  /** The "show your work" endpoint behind every risk score in the UI. */
  @Get('findings/:id')
  @RequirePermissions('finding:read')
  explain(@CurrentOrg() orgId: string, @Param('id') id: string) {
    return this.scoring.score(orgId, id);
  }

  @Post('findings/:id/evaluate')
  @RequirePermissions('policy:read')
  evaluate(@CurrentOrg() orgId: string, @Param('id') id: string) {
    return this.policy.evaluate(orgId, id);
  }

  @Get('policies')
  @RequirePermissions('policy:read')
  listPolicies(@CurrentOrg() orgId: string) {
    return this.prisma.withOrg(orgId, (tx) => tx.policy.findMany({ orderBy: { priority: 'asc' } }));
  }

  @Post('policies')
  @RequirePermissions('policy:write')
  createPolicy(@CurrentOrg() orgId: string, @Body() body: Record<string, unknown>) {
    // TODO: validate with the Policy contract once the create DTO settles.
    return this.prisma.withOrg(orgId, (tx) => tx.policy.create({ data: { ...body, orgId } }));
  }
}

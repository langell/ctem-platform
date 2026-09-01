import { Body, Controller, Get, Param, Patch, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CurrentOrg, RequirePermissions } from '@ctem/auth';
import { RiskScoringService } from './risk-scoring.service';
import { PolicyEngineService } from '../policy/policy-engine.service';
import { PolicyService } from '../policy/policy.service';
import { EnrichmentService } from '../feed/enrichment.service';

@ApiTags('risk')
@Controller('internal/risk')
export class RiskController {
  constructor(
    private readonly scoring: RiskScoringService,
    private readonly policy: PolicyEngineService,
    private readonly policies: PolicyService,
    private readonly enrichment: EnrichmentService,
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
    return this.policies.list(orgId);
  }

  @Get('policies/:id')
  @RequirePermissions('policy:read')
  getPolicy(@CurrentOrg() orgId: string, @Param('id') id: string) {
    return this.policies.get(orgId, id);
  }

  /**
   * Ops trigger for the threat-intel refresh that otherwise runs on a timer.
   * Platform-wide by nature; gated on the most admin-ish permission we have.
   */
  @Post('feed/refresh')
  @RequirePermissions('integration:manage')
  refreshFeed() {
    return this.enrichment.refresh();
  }

  @Post('policies')
  @RequirePermissions('policy:write')
  createPolicy(@CurrentOrg() orgId: string, @Body() body: unknown) {
    // Raw body so a tenant webhook URL is refused before zod strips unknown keys.
    return this.policies.create(orgId, body);
  }

  @Patch('policies/:id')
  @RequirePermissions('policy:write')
  updatePolicy(@CurrentOrg() orgId: string, @Param('id') id: string, @Body() body: unknown) {
    return this.policies.update(orgId, id, body);
  }
}

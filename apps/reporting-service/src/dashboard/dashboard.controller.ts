import { Controller, Get, Query } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CurrentOrg, RequirePermissions } from '@ctem/auth';
import { DashboardService } from './dashboard.service';

@ApiTags('reporting')
@Controller('internal/reporting')
export class DashboardController {
  constructor(private readonly dashboard: DashboardService) {}

  @Get('summary')
  @RequirePermissions('report:read')
  summary(@CurrentOrg() orgId: string) {
    return this.dashboard.summary(orgId);
  }

  @Get('trend')
  @RequirePermissions('report:read')
  trend(@CurrentOrg() orgId: string, @Query('days') days = '90') {
    return this.dashboard.trend(orgId, Number(days));
  }
}

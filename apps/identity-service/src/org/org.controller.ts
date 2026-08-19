import { Body, Controller, Get, Param, Patch } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CurrentOrg, CurrentUser, RequirePermissions } from '@ctem/auth';
import { Role, type Principal } from '@ctem/contracts';
import { OrgService } from './org.service';

@ApiTags('identity')
@Controller('internal/org')
export class OrgController {
  constructor(private readonly orgs: OrgService) {}

  @Get('members')
  @RequirePermissions('org:read')
  members(@CurrentOrg() orgId: string) {
    return this.orgs.members(orgId);
  }

  @Patch('members/:userId/role')
  @RequirePermissions('member:manage')
  setRole(
    @CurrentOrg() orgId: string,
    @CurrentUser() actor: Principal,
    @Param('userId') userId: string,
    @Body('role') role: string,
  ) {
    return this.orgs.setRole(orgId, actor.role, userId, Role.parse(role));
  }
}

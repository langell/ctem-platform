import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CurrentOrg, CurrentUser, RequirePermissions } from '@ctem/auth';
import { InviteMemberRequest, SetMemberRoleRequest, type Principal } from '@ctem/contracts';
import { ZodBody } from '@ctem/service-kit';
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

  /**
   * CTEM-side invite (the only add path). Membership is created on first login
   * when the IdP email matches this pending invite — not via Keycloak Admin API.
   */
  @Post('members')
  @HttpCode(201)
  @RequirePermissions('member:manage')
  invite(
    @CurrentOrg() orgId: string,
    @CurrentUser() actor: Principal,
    @Body(new ZodBody(InviteMemberRequest)) body: InviteMemberRequest,
  ) {
    return this.orgs.invite(orgId, actor, body);
  }

  @Patch('members/:userId/role')
  @RequirePermissions('member:manage')
  setRole(
    @CurrentOrg() orgId: string,
    @CurrentUser() actor: Principal,
    @Param('userId') userId: string,
    @Body(new ZodBody(SetMemberRoleRequest)) body: SetMemberRoleRequest,
  ) {
    return this.orgs.setRole(orgId, actor, userId, body.role);
  }

  /** Soft-disable Membership so the next JWT request 403s. Does not delete User. */
  @Delete('members/:userId')
  @RequirePermissions('member:manage')
  disable(
    @CurrentOrg() orgId: string,
    @CurrentUser() actor: Principal,
    @Param('userId') userId: string,
  ) {
    return this.orgs.disable(orgId, actor, userId);
  }
}

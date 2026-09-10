import { Body, Controller, Delete, Get, Param, Patch, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { RequirePermissions } from '@ctem/auth';
import type { InviteMemberRequest, SetMemberRoleRequest } from '@ctem/contracts';
import { ServiceProxy } from '../proxy/service-proxy';

/**
 * Tenant member admin. Org comes from the JWT (or PAT), never the client.
 * Forwards to identity-service only — no new service, no Keycloak Admin API.
 */
@ApiTags('members')
@ApiBearerAuth()
@Controller('v1/org/members')
export class OrgMembersProxyController {
  constructor(private readonly proxy: ServiceProxy) {}

  @Get()
  @RequirePermissions('org:read')
  list(@Req() req: never) {
    return this.proxy.forward('identity', 'GET', '/internal/org/members', req);
  }

  @Post()
  @RequirePermissions('member:manage')
  invite(@Req() req: never, @Body() body: InviteMemberRequest) {
    return this.proxy.forward('identity', 'POST', '/internal/org/members', req, { body });
  }

  @Patch(':userId/role')
  @RequirePermissions('member:manage')
  setRole(@Req() req: never, @Param('userId') userId: string, @Body() body: SetMemberRoleRequest) {
    return this.proxy.forward('identity', 'PATCH', `/internal/org/members/${userId}/role`, req, {
      body,
    });
  }

  @Delete(':userId')
  @RequirePermissions('member:manage')
  disable(@Req() req: never, @Param('userId') userId: string) {
    return this.proxy.forward('identity', 'DELETE', `/internal/org/members/${userId}`, req);
  }
}

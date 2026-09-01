import { Body, Controller, Get, Param, Patch, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { RequirePermissions } from '@ctem/auth';
import type { CreatePolicyRequest, UpdatePolicyRequest } from '@ctem/contracts';
import { ServiceProxy } from '../proxy/service-proxy';

/**
 * Tenant policy editor. Org comes from the JWT (or PAT), never the client.
 * Forwards to risk-service only — no new service, no query-forwarding of org.
 */
@ApiTags('policies')
@ApiBearerAuth()
@Controller('v1/policies')
export class PoliciesProxyController {
  constructor(private readonly proxy: ServiceProxy) {}

  @Get()
  @RequirePermissions('policy:read')
  list(@Req() req: never) {
    return this.proxy.forward('risk', 'GET', '/internal/risk/policies', req);
  }

  @Get(':id')
  @RequirePermissions('policy:read')
  get(@Req() req: never, @Param('id') id: string) {
    return this.proxy.forward('risk', 'GET', `/internal/risk/policies/${id}`, req);
  }

  @Post()
  @RequirePermissions('policy:write')
  create(@Req() req: never, @Body() body: CreatePolicyRequest) {
    return this.proxy.forward('risk', 'POST', '/internal/risk/policies', req, { body });
  }

  @Patch(':id')
  @RequirePermissions('policy:write')
  update(@Req() req: never, @Param('id') id: string, @Body() body: UpdatePolicyRequest) {
    return this.proxy.forward('risk', 'PATCH', `/internal/risk/policies/${id}`, req, { body });
  }
}

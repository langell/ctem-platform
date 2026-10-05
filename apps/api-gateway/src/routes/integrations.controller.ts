import { Body, Controller, Delete, Get, HttpCode, Param, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { RequirePermissions } from '@ctem/auth';
import type { ConnectGitHubRequest } from '@ctem/contracts';
import { ServiceProxy } from '../proxy/service-proxy';

/**
 * Tenant GitHub connect. Org comes from the principal. The body is forwarded
 * for asset-service to validate; this controller does not log it.
 */
@ApiTags('integrations')
@ApiBearerAuth()
@Controller('v1/integrations')
export class IntegrationsProxyController {
  constructor(private readonly proxy: ServiceProxy) {}

  @Get()
  @RequirePermissions('integration:manage')
  list(@Req() req: never) {
    return this.proxy.forward('asset', 'GET', '/internal/integrations', req);
  }

  @Post('github')
  @HttpCode(201)
  @RequirePermissions('integration:manage')
  connect(@Req() req: never, @Body() body: ConnectGitHubRequest) {
    return this.proxy.forward('asset', 'POST', '/internal/integrations/github', req, { body });
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermissions('integration:manage')
  remove(@Req() req: never, @Param('id') id: string) {
    return this.proxy.forward('asset', 'DELETE', `/internal/integrations/${id}`, req);
  }
}

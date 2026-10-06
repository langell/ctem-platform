import { Body, Controller, Delete, Get, HttpCode, Param, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CurrentOrg, RequirePermissions } from '@ctem/auth';
import { ConnectGitHubRequest } from '@ctem/contracts';
import { ZodBody } from '@ctem/service-kit';
import { IntegrationsService } from './integrations.service';

/** Internal API — the gateway supplies the principal. Org is never taken from the body. */
@ApiTags('integrations')
@Controller('internal/integrations')
export class IntegrationsController {
  constructor(private readonly integrations: IntegrationsService) {}

  @Get()
  @RequirePermissions('integration:manage')
  list(@CurrentOrg() orgId: string) {
    return this.integrations.list(orgId);
  }

  @Post('github')
  @HttpCode(201)
  @RequirePermissions('integration:manage')
  connectGitHub(
    @CurrentOrg() orgId: string,
    @Body(new ZodBody(ConnectGitHubRequest)) body: ConnectGitHubRequest,
  ) {
    return this.integrations.connectGitHub(orgId, body);
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermissions('integration:manage')
  remove(@CurrentOrg() orgId: string, @Param('id') id: string) {
    return this.integrations.remove(orgId, id);
  }
}

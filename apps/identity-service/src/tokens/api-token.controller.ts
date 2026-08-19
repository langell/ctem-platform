import { Body, Controller, Delete, Param, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CurrentOrg, Public, RequirePermissions } from '@ctem/auth';
import { ApiTokenService } from './api-token.service';

@ApiTags('identity')
@Controller('internal/tokens')
export class ApiTokenController {
  constructor(private readonly tokens: ApiTokenService) {}

  @Post()
  @RequirePermissions('integration:manage')
  issue(
    @CurrentOrg() orgId: string,
    @Body() body: { name: string; scopes?: string[]; expiresAt?: string },
  ) {
    return this.tokens.issue(
      orgId,
      body.name,
      body.scopes ?? ['scan:run', 'finding:read'],
      body.expiresAt ? new Date(body.expiresAt) : undefined,
    );
  }

  @Delete(':id')
  @RequirePermissions('integration:manage')
  revoke(@CurrentOrg() orgId: string, @Param('id') id: string) {
    return this.tokens.revoke(orgId, id);
  }

  /**
   * Called by the gateway when a caller presents a PAT instead of a JWT.
   * Reachable only inside the mesh; never routed publicly.
   */
  @Public()
  @Post('verify')
  verify(@Body('token') token: string) {
    return this.tokens.verify(token);
  }
}

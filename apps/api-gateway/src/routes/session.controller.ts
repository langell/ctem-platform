import { Controller, Get } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { CurrentUser } from '@ctem/auth';
import type { Principal } from '@ctem/contracts';

/**
 * Thin echo of the gateway-minted principal. Org is whatever the JWT (or PAT)
 * already carried — the client cannot supply one.
 */
@ApiTags('session')
@ApiBearerAuth()
@Controller('v1/session')
export class SessionController {
  @Get()
  me(@CurrentUser() user: Principal) {
    return {
      userId: user.userId,
      orgId: user.orgId,
      role: user.role,
      permissions: user.permissions,
      serviceAccount: user.serviceAccount,
    };
  }
}

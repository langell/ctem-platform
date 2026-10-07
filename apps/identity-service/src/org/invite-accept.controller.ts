import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { Public } from '@ctem/auth';
import { InternalAcceptInviteRequest } from '@ctem/contracts';
import { ZodBody } from '@ctem/service-kit';
import { OrgService } from './org.service';

/**
 * Mesh-only invite accept. The gateway passes the verified JWT `sub`.
 * The token is the only client field.
 */
@ApiTags('identity')
@Controller('internal/invites')
export class InviteAcceptController {
  constructor(private readonly orgs: OrgService) {}

  @Public()
  @Post('accept')
  @HttpCode(200)
  accept(@Body(new ZodBody(InternalAcceptInviteRequest)) body: InternalAcceptInviteRequest) {
    return this.orgs.acceptInviteByToken(body.sub, body.token);
  }
}

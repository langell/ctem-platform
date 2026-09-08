import { Body, Controller, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { Public } from '@ctem/auth';
import { ResolveJwtRequest } from '@ctem/contracts';
import { ZodBody } from '@ctem/service-kit';
import { OrgService } from './org.service';

/**
 * Called by the gateway after JWT verify. Mesh-only (same as PAT verify).
 * Never accepts a role from the caller — Membership is the only AuthZ source.
 */
@ApiTags('identity')
@Controller('internal/auth')
export class AuthResolveController {
  constructor(private readonly orgs: OrgService) {}

  @Public()
  @Post('resolve')
  resolve(@Body(new ZodBody(ResolveJwtRequest)) body: ResolveJwtRequest) {
    return this.orgs.resolveJwt(body);
  }
}

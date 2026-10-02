import { Body, Controller, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { Public } from '@ctem/auth';
import { ResolveJwtRequest, ResolveMembershipsRequest } from '@ctem/contracts';
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

  /**
   * Active memberships for a verified subject when the JWT has no org_id.
   * Mesh-only. The caller does not choose which user's rows come back.
   */
  @Public()
  @Post('memberships')
  memberships(@Body(new ZodBody(ResolveMembershipsRequest)) body: ResolveMembershipsRequest) {
    return this.orgs.resolveActiveMemberships(body);
  }
}

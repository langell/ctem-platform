import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { Public } from '@ctem/auth';
import { InternalCreateOrgRequest } from '@ctem/contracts';
import { ZodBody } from '@ctem/service-kit';
import { OrgService } from './org.service';

/**
 * Mesh-only org bootstrap. The gateway passes the verified JWT `sub`.
 * Name and slug are the only client fields; role is owner and plan stays trial.
 */
@ApiTags('identity')
@Controller('internal/orgs')
export class CreateOrgController {
  constructor(private readonly orgs: OrgService) {}

  @Public()
  @Post()
  @HttpCode(201)
  create(@Body(new ZodBody(InternalCreateOrgRequest)) body: InternalCreateOrgRequest) {
    return this.orgs.createOrgForSubject(body.sub, body.name, body.slug);
  }
}

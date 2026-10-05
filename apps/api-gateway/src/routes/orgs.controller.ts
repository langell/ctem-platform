import {
  Body,
  Controller,
  HttpCode,
  HttpException,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { loadEnv } from '@ctem/config';
import { CreateOrgRequest, CreateOrgResponse, InternalCreateOrgRequest } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';
import { ZodBody } from '@ctem/service-kit';

const log = rootLogger.child({ component: 'gateway-orgs' });

/**
 * Create the caller's first organization. Body is name and slug only.
 * The owner is the JIT user for the verified JWT `sub` — never a client field.
 * PATs and missing bearers are rejected by the gateway guard (401).
 */
@ApiTags('orgs')
@ApiBearerAuth()
@Controller('v1/orgs')
export class OrgsProxyController {
  @Post()
  @HttpCode(201)
  create(
    @Req() req: { verifiedSub?: string },
    @Body(new ZodBody(CreateOrgRequest)) body: CreateOrgRequest,
  ) {
    const sub = req.verifiedSub;
    if (!sub) throw new UnauthorizedException('Token verification failed');
    const internal = InternalCreateOrgRequest.parse({ name: body.name, slug: body.slug, sub });
    return createOrgInIdentity(internal);
  }
}

async function createOrgInIdentity(body: InternalCreateOrgRequest): Promise<CreateOrgResponse> {
  const env = loadEnv();
  const url = `${env.IDENTITY_SERVICE_URL}/internal/orgs`;

  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5_000),
    });
  } catch (err) {
    log.error({ err }, 'identity-service unreachable for org create');
    throw new UnauthorizedException('Token verification failed');
  }

  const payload = (await res.json().catch(() => null)) as unknown;
  if (!res.ok) {
    throw new HttpException(payload ?? { title: 'Upstream error', status: res.status }, res.status);
  }

  const parsed = CreateOrgResponse.safeParse(payload);
  if (!parsed.success) throw new UnauthorizedException('Token verification failed');
  return parsed.data;
}

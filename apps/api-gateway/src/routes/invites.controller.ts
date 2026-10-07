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
import {
  AcceptInviteRequest,
  AcceptInviteResponse,
  InternalAcceptInviteRequest,
} from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';
import { ZodBody } from '@ctem/service-kit';

const log = rootLogger.child({ component: 'gateway-invites' });

/**
 * Accept an invite token for the verified JWT subject. Body is the token only.
 * A member may call this and receive 409 when they already belong to an org.
 * PATs and missing bearers are rejected by the gateway guard (401).
 */
@ApiTags('invites')
@ApiBearerAuth()
@Controller('v1/invites')
export class InvitesProxyController {
  @Post('accept')
  @HttpCode(200)
  accept(
    @Req() req: { verifiedSub?: string },
    @Body(new ZodBody(AcceptInviteRequest)) body: AcceptInviteRequest,
  ) {
    const sub = req.verifiedSub;
    if (!sub) throw new UnauthorizedException('Token verification failed');
    const internal = InternalAcceptInviteRequest.parse({ sub, token: body.token });
    return acceptInviteInIdentity(internal);
  }
}

async function acceptInviteInIdentity(
  body: InternalAcceptInviteRequest,
): Promise<AcceptInviteResponse> {
  const env = loadEnv();
  const url = `${env.IDENTITY_SERVICE_URL}/internal/invites/accept`;

  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5_000),
    });
  } catch (err) {
    log.error({ err }, 'identity-service unreachable for invite accept');
    throw new UnauthorizedException('Token verification failed');
  }

  const payload = (await res.json().catch(() => null)) as unknown;
  if (!res.ok) {
    throw new HttpException(payload ?? { title: 'Upstream error', status: res.status }, res.status);
  }

  const parsed = AcceptInviteResponse.safeParse(payload);
  if (!parsed.success) throw new UnauthorizedException('Token verification failed');
  return parsed.data;
}

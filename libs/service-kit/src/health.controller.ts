import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { Public } from '@ctem/auth';
import { loadEnv } from '@ctem/config';

/**
 * Liveness and readiness are separate on purpose: a service whose NATS
 * connection is down should stop taking traffic without being restarted.
 */
@ApiTags('health')
@Controller('health')
export class HealthController {
  private readonly startedAt = Date.now();

  @Public()
  @Get('live')
  live(): { status: string; service: string; uptimeSec: number } {
    return {
      status: 'ok',
      service: loadEnv().SERVICE_NAME,
      uptimeSec: Math.round((Date.now() - this.startedAt) / 1000),
    };
  }

  @Public()
  @Get('ready')
  ready(): { status: string } {
    // TODO: aggregate dependency checks (db, nats, s3) via @nestjs/terminus.
    return { status: 'ok' };
  }
}

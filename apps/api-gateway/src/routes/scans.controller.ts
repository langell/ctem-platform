import { Body, Controller, Get, Headers, Param, Post, Query, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { RequirePermissions } from '@ctem/auth';
import type { CreateScanRequest, IngestSbomRequest } from '@ctem/contracts';
import { ServiceProxy } from '../proxy/service-proxy';

/**
 * CI and deploy tooling poll GET /v1/scans/:id with a PAT. `conclusion` is
 * computed upstream from matching fail_build rules; `deployConclusion` from
 * matching block_deploy. This proxy has no POST/PATCH for either and does not
 * call GitHub Checks, Deployments, or GitLab Commit Statuses / Deployments
 * (orchestrator publishes Checks and GitLab statuses on scanCompleted from
 * concludeScan only, and GitHub / GitLab Deployment updates from
 * concludeDeploy only — all additive). Org comes from the token. CORS and
 * unknown query forwarding stay comments.
 */
@ApiTags('scans')
@ApiBearerAuth()
@Controller('v1/scans')
export class ScansProxyController {
  constructor(private readonly proxy: ServiceProxy) {}

  @Get()
  @RequirePermissions('scan:read')
  list(@Req() req: never, @Query() query: Record<string, string>) {
    return this.proxy.forward('orchestrator', 'GET', '/internal/scans', req, { query });
  }

  @Get(':id')
  @RequirePermissions('scan:read')
  get(@Req() req: never, @Param('id') id: string) {
    return this.proxy.forward('orchestrator', 'GET', `/internal/scans/${id}`, req);
  }

  @Post()
  @RequirePermissions('scan:run')
  create(
    @Req() req: never,
    @Headers('idempotency-key') idempotencyKey: string | string[] | undefined,
    @Body() body: CreateScanRequest,
  ) {
    return this.proxy.forward('orchestrator', 'POST', '/internal/scans', req, {
      body,
      headers: idempotencyForwardHeaders(idempotencyKey),
    });
  }

  /** CI uploads an SBOM instead of granting us repo access — the fastest path to first value. */
  @Post('sbom')
  @RequirePermissions('scan:run')
  ingestSbom(
    @Req() req: never,
    @Headers('idempotency-key') idempotencyKey: string | string[] | undefined,
    @Body() body: IngestSbomRequest,
  ) {
    return this.proxy.forward('orchestrator', 'POST', '/internal/scans/sbom', req, {
      body,
      headers: idempotencyForwardHeaders(idempotencyKey),
    });
  }
}

/**
 * Forward the client key so orchestrator can dedupe the accept. The gateway
 * does not emit `scan.kick`. Principal headers are applied by the proxy after
 * this map, so a client cannot override them by naming the same header.
 */
function idempotencyForwardHeaders(
  value: string | string[] | undefined,
): Record<string, string> | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  const key = raw?.trim();
  if (!key) return undefined;
  return { 'idempotency-key': key };
}

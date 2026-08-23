import { Body, Controller, Get, Param, Post, Query } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CurrentOrg, CurrentUser, RequirePermissions } from '@ctem/auth';
import { CreateScanRequest, IngestSbomRequest, type Principal } from '@ctem/contracts';
import { ZodBody } from '@ctem/service-kit';
import { PrismaService } from '@ctem/db';
import { ArtifactStore } from '@ctem/storage';
import { ScanDispatcherService } from './scan-dispatcher.service';

@ApiTags('scans')
@Controller('internal/scans')
export class ScansController {
  constructor(
    private readonly dispatcher: ScanDispatcherService,
    private readonly prisma: PrismaService,
    private readonly artifacts: ArtifactStore,
  ) {}

  @Get()
  @RequirePermissions('scan:read')
  list(@CurrentOrg() orgId: string, @Query('limit') limit = '50') {
    return this.prisma.withOrg(orgId, (tx) =>
      tx.scan.findMany({ orderBy: { createdAt: 'desc' }, take: Math.min(Number(limit), 200) }),
    );
  }

  @Get(':id')
  @RequirePermissions('scan:read')
  get(@CurrentOrg() orgId: string, @Param('id') id: string) {
    return this.prisma.withOrg(orgId, (tx) =>
      tx.scan.findUniqueOrThrow({ where: { id }, include: { jobs: true } }),
    );
  }

  @Post()
  @RequirePermissions('scan:run')
  create(
    @CurrentOrg() orgId: string,
    @CurrentUser() user: Principal,
    @Body(new ZodBody(CreateScanRequest)) body: CreateScanRequest,
  ) {
    return this.dispatcher.createScan(orgId, user.userId, body, 'manual');
  }

  /**
   * SBOM ingest path: CI has already produced a CycloneDX doc, so we skip
   * cloning and go straight to vulnerability matching.
   */
  @Post('sbom')
  @RequirePermissions('scan:run')
  async ingestSbom(
    @CurrentOrg() orgId: string,
    @CurrentUser() user: Principal,
    @Body(new ZodBody(IngestSbomRequest)) body: IngestSbomRequest,
  ) {
    const asset = await this.prisma.withOrg(orgId, (tx) =>
      tx.asset.findUniqueOrThrow({
        where: { orgId_externalKey: { orgId, externalKey: body.assetExternalKey } },
      }),
    );

    // CI can hand us the document inline instead of pre-uploading it.
    const artifactKey =
      body.artifactKey ??
      (await this.artifacts.putJson(
        this.artifacts.key(orgId, 'sbom', asset.id, `${Date.now()}.json`),
        body.document,
      ));

    return this.dispatcher.createScan(
      orgId,
      user.userId,
      {
        scannerType: 'sca',
        assetSelector: { assetIds: [asset.id] },
        options: { sbomArtifactKey: artifactKey, format: body.format, ref: body.ref },
      },
      'ci',
    );
  }

  @Post('jobs/:jobId/retry')
  @RequirePermissions('scan:run')
  retry(@CurrentOrg() orgId: string, @Param('jobId') jobId: string) {
    return this.dispatcher.retryJob(orgId, jobId);
  }
}

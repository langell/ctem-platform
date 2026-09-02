import { Body, Controller, Get, NotFoundException, Param, Post, Query } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CurrentOrg, CurrentUser, RequirePermissions } from '@ctem/auth';
import {
  CreateScanRequest,
  IngestSbomRequest,
  concludeScan,
  type Principal,
  type PolicyCondition,
} from '@ctem/contracts';
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

  /**
   * CI-facing GET. Org comes from the token (JWT or PAT), never the client.
   * Conclusion is computed from matching fail_build rules — there is no write
   * path for it. CORS and unknown query forwarding stay comments.
   */
  @Get(':id')
  @RequirePermissions('scan:read')
  async get(@CurrentOrg() orgId: string, @Param('id') id: string) {
    const result = await this.prisma.withOrg(orgId, async (tx) => {
      const scan = await tx.scan.findUnique({ where: { id }, include: { jobs: true } });
      // RLS fail-closed looks the same as a missing row. Never 500 — that is how
      // a cross-tenant GET /v1/scans/:id would leak that the id exists (P2025).
      if (!scan) return null;

      if (scan.status === 'queued' || scan.status === 'running') {
        return { ...scan, conclusion: 'pending' as const };
      }

      const jobs = scan.jobs ?? [];
      const assetIds = [...new Set(jobs.map((job) => job.assetId))];
      const expectedFindingCount = jobs.reduce((n, job) => n + (job.findingCount ?? 0), 0);

      const findings = assetIds.length
        ? await tx.finding.findMany({
            where: {
              assetId: { in: assetIds },
              scannerType: scan.scannerType,
              state: { in: ['open', 'triaged', 'in_progress'] },
            },
            include: { asset: true },
          })
        : [];

      const policies = await tx.policy.findMany({
        where: { enabled: true },
        orderBy: { priority: 'asc' },
      });

      const now = new Date();
      const exceptions = await tx.riskException.findMany({
        where: {
          revokedAt: null,
          approvedAt: { not: null },
          expiresAt: { gt: now },
          OR: [
            { scope: 'global' },
            { scope: 'finding', targetRef: { in: findings.map((row) => row.id) } },
          ],
        },
      });

      const suppressedFindingIds = new Set<string>();
      if (exceptions.some((row) => row.scope === 'global')) {
        for (const row of findings) suppressedFindingIds.add(row.id);
      } else {
        for (const row of exceptions) suppressedFindingIds.add(row.targetRef);
      }

      return {
        ...scan,
        conclusion: concludeScan({
          status: scan.status,
          findings: findings.map((row) => ({
            id: row.id,
            severity: row.severity,
            riskScore: row.riskScore,
            kev: row.kev,
            epssScore: row.epssScore,
            fixAvailable: row.fixAvailable,
            scannerType: row.scannerType,
            asset: {
              kind: row.asset.kind,
              exposure: row.asset.exposure,
              criticality: row.asset.criticality,
              tags: row.asset.tags,
            },
          })),
          policies: policies.map((policy) => ({
            enabled: policy.enabled,
            priority: policy.priority,
            condition: policy.condition as PolicyCondition,
            actions: policy.actions,
          })),
          suppressedFindingIds,
          expectedFindingCount,
        }),
      };
    });
    if (!result) throw new NotFoundException(`Scan ${id} not found`);
    return result;
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

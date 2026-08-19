import { Injectable } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { rootLogger } from '@ctem/observability';
import type { CreateScanRequest, ScannerType } from '@ctem/contracts';

/**
 * Turns "scan my SCA surface" into a concrete list of assets. Each scanner type
 * only applies to certain asset kinds, so planning is where we avoid dispatching
 * a SAST job at a DNS record.
 */
export const SCANNER_ASSET_KINDS: Record<ScannerType, string[]> = {
  sca: ['repository', 'package', 'container_image'],
  sast: ['repository'],
  container: ['container_image', 'kubernetes_workload'],
  iac: ['repository', 'iac_stack'],
  secrets: ['repository'],
  asm: ['domain', 'ip_range', 'web_application', 'api_endpoint', 'host'],
  cloud_posture: ['cloud_resource', 'kubernetes_workload'],
};

@Injectable()
export class ScanPlannerService {
  private readonly log = rootLogger.child({ component: 'scan-planner' });

  constructor(private readonly prisma: PrismaService) {}

  async plan(
    orgId: string,
    scannerType: ScannerType,
    selector: CreateScanRequest['assetSelector'],
  ): Promise<Array<{ id: string; kind: string; externalKey: string; attributes: unknown }>> {
    const kinds = selector.kinds?.length
      ? selector.kinds.filter((k) => SCANNER_ASSET_KINDS[scannerType].includes(k))
      : SCANNER_ASSET_KINDS[scannerType];

    const assets = await this.prisma.withOrg(orgId, (tx) =>
      tx.asset.findMany({
        where: {
          archivedAt: null,
          kind: { in: kinds },
          ...(selector.assetIds?.length ? { id: { in: selector.assetIds } } : {}),
          // Tag filters use JSON containment so `{team: "payments"}` matches.
          ...(selector.tags ? { tags: { equals: selector.tags as object } } : {}),
        },
        select: { id: true, kind: true, externalKey: true, attributes: true },
      }),
    );

    this.log.info({ scannerType, count: assets.length }, 'scan planned');
    return assets;
  }
}

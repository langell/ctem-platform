import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { EventBus } from '@ctem/events';
import { SUBJECTS, type ListAssetsQuery, type UpsertAssetRequest } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';

/**
 * Assets are upserted, never blindly inserted: connectors re-run constantly and
 * an asset's identity is its `externalKey`, not a row id we happened to mint.
 */
@Injectable()
export class AssetsService {
  private readonly log = rootLogger.child({ component: 'assets' });

  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: EventBus,
  ) {}

  async upsert(orgId: string, input: UpsertAssetRequest, integrationId?: string) {
    const { asset, created } = await this.prisma.withOrg(orgId, async (tx) => {
      const existing = await tx.asset.findUnique({
        where: { orgId_externalKey: { orgId, externalKey: input.externalKey } },
      });

      const data = {
        orgId,
        kind: input.kind,
        externalKey: input.externalKey,
        name: input.name,
        source: input.source,
        exposure: input.exposure ?? existing?.exposure ?? 'unknown',
        criticality: input.criticality ?? existing?.criticality ?? 'unknown',
        dataClasses: input.dataClasses ?? existing?.dataClasses ?? [],
        ownerTeam: input.ownerTeam ?? existing?.ownerTeam ?? null,
        ownerEmail: input.ownerEmail ?? existing?.ownerEmail ?? null,
        tags: (input.tags ?? existing?.tags ?? {}) as object,
        attributes: (input.attributes ?? existing?.attributes ?? {}) as object,
        lastSeenAt: new Date(),
        archivedAt: null,
        integrationId: integrationId ?? existing?.integrationId ?? null,
      };

      const row = await tx.asset.upsert({
        where: { orgId_externalKey: { orgId, externalKey: input.externalKey } },
        create: data,
        update: data,
      });
      return { asset: row, created: !existing };
    });

    await this.bus.publish(created ? SUBJECTS.assetDiscovered : SUBJECTS.assetUpdated, orgId, {
      ...asset,
      dataClasses: asset.dataClasses,
      tags: asset.tags ?? {},
      attributes: asset.attributes ?? {},
    });

    this.log.info({ assetId: asset.id, created }, 'asset upserted');
    return asset;
  }

  async list(orgId: string, query: ListAssetsQuery) {
    return this.prisma.withOrg(orgId, async (tx) => {
      const items = await tx.asset.findMany({
        where: {
          archivedAt: null,
          ...(query.kind ? { kind: query.kind } : {}),
          ...(query.exposure ? { exposure: query.exposure } : {}),
          ...(query.criticality ? { criticality: query.criticality } : {}),
          ...(query.ownerTeam ? { ownerTeam: query.ownerTeam } : {}),
          ...(query.q ? { name: { contains: query.q, mode: 'insensitive' as const } } : {}),
        },
        orderBy: { lastSeenAt: 'desc' },
        take: query.limit + 1,
        ...(query.cursor ? { cursor: { id: query.cursor }, skip: 1 } : {}),
      });

      const hasMore = items.length > query.limit;
      const page = hasMore ? items.slice(0, query.limit) : items;
      return { items: page, nextCursor: hasMore ? (page.at(-1)?.id ?? null) : null };
    });
  }

  async get(orgId: string, id: string) {
    const asset = await this.prisma.withOrg(orgId, (tx) => tx.asset.findUnique({ where: { id } }));
    // RLS fail-closed looks the same as a missing row. Never 500 — that is how
    // a cross-tenant GET /v1/assets/:id would leak that the id exists (P2025).
    if (!asset) throw new NotFoundException(`Asset ${id} not found`);
    return asset;
  }

  /**
   * Connectors mark what they saw; anything not seen in this sync is archived
   * rather than deleted, so historical findings keep their asset context.
   * Scoped to the discovering integration — two GitHub or GitLab integrations
   * in one org must not archive each other's inventory.
   */
  async archiveStale(orgId: string, source: string, seenBefore: Date, integrationId: string) {
    return this.prisma.withOrg(orgId, (tx) =>
      tx.asset.updateMany({
        where: { source, integrationId, lastSeenAt: { lt: seenBefore }, archivedAt: null },
        data: { archivedAt: new Date() },
      }),
    );
  }
}

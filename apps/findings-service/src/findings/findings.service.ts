import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '@ctem/db';
import { EventBus } from '@ctem/events';
import {
  SUBJECTS,
  type FindingsReportedPayload,
  type ListFindingsQuery,
  type TriageFindingRequest,
} from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';
import { FindingNormalizer } from './finding-normalizer';

@Injectable()
export class FindingsService {
  private readonly log = rootLogger.child({ component: 'findings' });

  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: EventBus,
    private readonly normalizer: FindingNormalizer,
  ) {}

  /**
   * Upserts a scanner's batch and closes anything it no longer reports for the
   * same (asset, scanner) pair. Auto-resolution is what keeps the backlog honest.
   */
  async ingest(orgId: string, payload: FindingsReportedPayload): Promise<void> {
    const seenAt = new Date();
    const collapsed = this.normalizer.collapseScan(payload.assetId, payload.findings);
    const fingerprints = collapsed.map((row) => row.fingerprint);

    for (const { fingerprint, finding: raw, location, evidence } of collapsed) {
      const severity = this.normalizer.reconcileSeverity(raw);

      const { finding, created } = await this.prisma.withOrg(orgId, async (tx) => {
        const existing = await tx.finding.findUnique({
          where: { orgId_fingerprint: { orgId, fingerprint } },
        });

        const row = await tx.finding.upsert({
          where: { orgId_fingerprint: { orgId, fingerprint } },
          create: {
            orgId,
            assetId: payload.assetId,
            fingerprint,
            scannerType: raw.scannerType,
            scannerName: raw.scannerName,
            title: raw.title,
            description: raw.description,
            severity,
            state: 'open',
            identifiers: raw.identifiers as object,
            cvssScore: raw.cvssScore,
            cvssVector: raw.cvssVector,
            epssScore: raw.epssScore,
            kev: raw.kev,
            location: location as object,
            evidence: evidence as object,
            fixAvailable: raw.fix.available,
            fixedVersion: raw.fix.fixedVersion ?? null,
            artifactKey: payload.artifactKey,
            firstSeenAt: seenAt,
            lastSeenAt: seenAt,
          },
          update: {
            // A re-reported finding refreshes evidence/location but never resets triage.
            lastSeenAt: seenAt,
            severity,
            cvssScore: raw.cvssScore,
            epssScore: raw.epssScore,
            kev: raw.kev,
            fixAvailable: raw.fix.available,
            fixedVersion: raw.fix.fixedVersion ?? null,
            location: location as object,
            evidence: evidence as object,
            artifactKey: payload.artifactKey,
            ...(existing?.state === 'resolved'
              ? { state: 'open', resolvedAt: null } // regression
              : {}),
          },
        });
        return { finding: row, created: !existing };
      });

      await this.bus.publish(
        created ? SUBJECTS.findingCreated : SUBJECTS.findingUpdated,
        orgId,
        this.toContract(finding),
      );
    }

    const closed = await this.prisma.withOrg(orgId, (tx) =>
      tx.finding.updateMany({
        where: {
          assetId: payload.assetId,
          scannerType: payload.scannerType,
          state: { in: ['open', 'triaged', 'in_progress'] },
          fingerprint: { notIn: fingerprints },
        },
        data: { state: 'resolved', resolvedAt: seenAt },
      }),
    );

    // Every new/changed finding needs a risk score; the risk service owns that.
    await this.bus.publish(SUBJECTS.riskRescoreRequested, orgId, { findingIds: [] });

    this.log.info(
      { assetId: payload.assetId, reported: payload.findings.length, autoResolved: closed.count },
      'findings ingested',
    );
  }

  async list(orgId: string, query: ListFindingsQuery) {
    return this.prisma.withOrg(orgId, async (tx) => {
      const items = await tx.finding.findMany({
        where: {
          ...(query.assetId ? { assetId: query.assetId } : {}),
          ...(query.scannerType ? { scannerType: query.scannerType } : {}),
          ...(query.severity ? { severity: query.severity } : {}),
          ...(query.state ? { state: query.state } : {}),
          ...(query.validation ? { validation: query.validation } : {}),
          ...(query.minRiskScore !== undefined ? { riskScore: { gte: query.minRiskScore } } : {}),
          ...(query.fixAvailable !== undefined ? { fixAvailable: query.fixAvailable } : {}),
          ...(query.slaBreached ? { slaDueAt: { lt: new Date() }, resolvedAt: null } : {}),
          ...(query.q ? { title: { contains: query.q, mode: 'insensitive' as const } } : {}),
        },
        orderBy: [{ riskScore: 'desc' }, { lastSeenAt: 'desc' }],
        take: query.limit + 1,
        ...(query.cursor ? { cursor: { id: query.cursor }, skip: 1 } : {}),
      });

      const hasMore = items.length > query.limit;
      const page = hasMore ? items.slice(0, query.limit) : items;
      return { items: page, nextCursor: hasMore ? (page.at(-1)?.id ?? null) : null };
    });
  }

  async get(orgId: string, id: string) {
    const finding = await this.prisma.withOrg(orgId, (tx) =>
      tx.finding.findUnique({ where: { id }, include: { events: true, asset: true } }),
    );
    if (!finding) throw new NotFoundException(`Finding ${id} not found`);
    return finding;
  }

  /** State changes are events, not just column writes — auditors need the trail. */
  async triage(orgId: string, id: string, actor: string, request: TriageFindingRequest) {
    const { previous, updated } = await this.prisma.withOrg(orgId, async (tx) => {
      const before = await tx.finding.findUniqueOrThrow({ where: { id } });
      const after = await tx.finding.update({
        where: { id },
        data: {
          state: request.state,
          resolvedAt: request.state === 'resolved' ? new Date() : null,
        },
      });
      await tx.findingEvent.create({
        data: {
          orgId,
          findingId: id,
          type: 'state_change',
          fromState: before.state,
          toState: request.state,
          actor,
          reason: request.reason,
          metadata: (request.expiresAt ? { expiresAt: request.expiresAt } : {}) as object,
        },
      });
      return { previous: before, updated: after };
    });

    await this.bus.publish(SUBJECTS.findingStateChanged, orgId, {
      findingId: id,
      from: previous.state,
      to: updated.state,
      actor,
    });
    return updated;
  }

  private toContract(row: Record<string, unknown>) {
    return {
      ...row,
      identifiers: row.identifiers ?? [],
      location: row.location ?? {},
    };
  }
}

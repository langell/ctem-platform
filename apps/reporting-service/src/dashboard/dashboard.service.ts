import { Injectable } from '@nestjs/common';
import { PrismaService } from '@ctem/db';

export interface ExposureSummary {
  openBySeverity: Record<string, number>;
  openByScanner: Record<string, number>;
  slaBreached: number;
  meanTimeToRemediateDays: number | null;
  topRisks: Array<{ id: string; title: string; riskScore: number; assetName: string }>;
  assetCoverage: { total: number; scannedLast7Days: number };
}

/**
 * Read-side aggregation. Today these are Postgres aggregates; the moment they
 * stop being fast, the same shapes get materialized into rollup tables (or a
 * columnar store) without changing the API.
 */
@Injectable()
export class DashboardService {
  constructor(private readonly prisma: PrismaService) {}

  async summary(orgId: string): Promise<ExposureSummary> {
    return this.prisma.withOrg(orgId, async (tx) => {
      const openStates = ['open', 'triaged', 'in_progress'];

      const [bySeverity, byScanner, slaBreached, topRisks, totalAssets, scannedAssets, mttr] =
        await Promise.all([
          tx.finding.groupBy({
            by: ['severity'],
            where: { state: { in: openStates } },
            _count: true,
          }),
          tx.finding.groupBy({
            by: ['scannerType'],
            where: { state: { in: openStates } },
            _count: true,
          }),
          tx.finding.count({
            where: { state: { in: openStates }, slaDueAt: { lt: new Date() } },
          }),
          tx.finding.findMany({
            where: { state: { in: openStates } },
            orderBy: { riskScore: 'desc' },
            take: 10,
            select: { id: true, title: true, riskScore: true, asset: { select: { name: true } } },
          }),
          tx.asset.count({ where: { archivedAt: null } }),
          tx.scanJob.findMany({
            where: {
              status: 'succeeded',
              finishedAt: { gte: new Date(Date.now() - 7 * 24 * 3_600_000) },
            },
            select: { assetId: true },
            distinct: ['assetId'],
          }),
          tx.$queryRawUnsafe<Array<{ avg_days: number | null }>>(
            `SELECT AVG(EXTRACT(EPOCH FROM ("resolvedAt" - "firstSeenAt")) / 86400)::float AS avg_days
             FROM findings
             WHERE "resolvedAt" IS NOT NULL
               AND "resolvedAt" > now() - interval '90 days'`,
          ),
        ]);

      return {
        openBySeverity: Object.fromEntries(bySeverity.map((r) => [r.severity, r._count])),
        openByScanner: Object.fromEntries(byScanner.map((r) => [r.scannerType, r._count])),
        slaBreached,
        meanTimeToRemediateDays: mttr[0]?.avg_days ?? null,
        topRisks: topRisks.map((f) => ({
          id: f.id,
          title: f.title,
          riskScore: f.riskScore,
          assetName: f.asset.name,
        })),
        assetCoverage: { total: totalAssets, scannedLast7Days: scannedAssets.length },
      };
    });
  }

  /** Daily open-finding counts, for the "are we actually getting better?" chart. */
  async trend(orgId: string, days = 90) {
    return this.prisma.withOrg(orgId, (tx) =>
      tx.$queryRawUnsafe<Array<{ day: Date; opened: number; resolved: number }>>(
        `SELECT d::date AS day,
                COUNT(*) FILTER (WHERE f."firstSeenAt"::date = d::date)::int AS opened,
                COUNT(*) FILTER (WHERE f."resolvedAt"::date = d::date)::int  AS resolved
         FROM generate_series(now() - ($1 || ' days')::interval, now(), '1 day') d
         LEFT JOIN findings f ON f."firstSeenAt"::date = d::date OR f."resolvedAt"::date = d::date
         GROUP BY d ORDER BY d`,
        String(days),
      ),
    );
  }
}

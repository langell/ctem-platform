import { Injectable, OnApplicationBootstrap, OnModuleDestroy } from '@nestjs/common';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import { EventBus } from '@ctem/events';
import { SUBJECTS } from '@ctem/contracts';
import { FeedStore } from './feed.store';
import { computeEpssUpdates, computeKevUpdates, type KevEntry } from './enrichment.logic';
import { fetchEpssPaged } from './epss.client';

const SIX_HOURS_MS = 6 * 3_600_000;

export interface EnrichmentSummary {
  advisories: number;
  kevChanged: number;
  epssChanged: number;
  findingsUpdated: number;
  orgsNotified: number;
}

/**
 * Keeps exploitability intel current after ingest. A finding's KEV flag and
 * EPSS score are snapshotted at scan time; this job refreshes the mirrored
 * advisories from the live KEV catalog and EPSS API, pushes changes down onto
 * open findings, and requests a rescore for every affected org — a CVE landing
 * on KEV overnight moves its risk scores before anyone re-scans.
 */
@Injectable()
export class EnrichmentService implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly log = rootLogger.child({ component: 'feed-enrichment' });
  private timer?: NodeJS.Timeout;
  private running = false;

  constructor(
    private readonly store: FeedStore,
    private readonly bus: EventBus,
  ) {}

  onApplicationBootstrap(): void {
    this.timer = setInterval(() => void this.safeRefresh(), SIX_HOURS_MS);
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private async safeRefresh(): Promise<void> {
    try {
      await this.refresh();
    } catch (err) {
      this.log.warn({ err }, 'enrichment refresh failed');
    }
  }

  async refresh(): Promise<EnrichmentSummary> {
    if (this.running) {
      this.log.warn('enrichment already running, skipping');
      return { advisories: 0, kevChanged: 0, epssChanged: 0, findingsUpdated: 0, orgsNotified: 0 };
    }
    this.running = true;
    try {
      return await this.doRefresh();
    } finally {
      this.running = false;
    }
  }

  private async doRefresh(): Promise<EnrichmentSummary> {
    const rows = await this.store.vulnerability.findMany({
      select: { id: true, aliases: true, kev: true, kevDueDate: true, epssScore: true },
    });

    const kevUpdates = computeKevUpdates(rows, await this.fetchKevCatalog());
    for (const u of kevUpdates) {
      await this.store.vulnerability.update({
        where: { id: u.id },
        data: { kev: u.kev, kevDueDate: u.kevDueDate },
      });
    }

    const epssUpdates = computeEpssUpdates(rows, await this.fetchEpssScores(rows));
    for (const u of epssUpdates) {
      await this.store.vulnerability.update({
        where: { id: u.id },
        data: { epssScore: u.epssScore, epssPercentile: u.epssPercentile },
      });
    }

    const { findingsUpdated, orgsNotified } = await this.propagate(kevUpdates, epssUpdates);

    const summary: EnrichmentSummary = {
      advisories: rows.length,
      kevChanged: kevUpdates.length,
      epssChanged: epssUpdates.length,
      findingsUpdated,
      orgsNotified,
    };
    this.log.info(summary, 'enrichment refresh complete');
    return summary;
  }

  private async fetchKevCatalog(): Promise<Map<string, KevEntry>> {
    const env = loadEnv();
    const res = await fetch(env.KEV_FEED_URL, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) throw new Error(`KEV feed returned ${res.status}`);
    const body = (await res.json()) as {
      vulnerabilities?: Array<{ cveID: string; dueDate?: string }>;
    };
    return new Map(
      (body.vulnerabilities ?? []).map((v) => [
        v.cveID,
        { dueDate: v.dueDate ? new Date(v.dueDate) : null },
      ]),
    );
  }

  private async fetchEpssScores(
    rows: Array<{ id: string; aliases: string[] }>,
  ): Promise<Map<string, { epss: number; percentile: number | null }>> {
    const env = loadEnv();
    const cves = [
      ...new Set(
        rows.map((r) => [r.id, ...r.aliases].find((a) => a.startsWith('CVE-'))).filter(Boolean),
      ),
    ] as string[];

    return fetchEpssPaged({
      apiUrl: env.EPSS_API_URL,
      cves,
      onPageError: (status) => {
        // Partial EPSS data is fine — enrich what we can, next sweep fills gaps.
        this.log.warn({ status }, 'EPSS page failed, continuing');
      },
    });
  }

  /**
   * Pushes changed intel onto open findings (matched by CVE identifier) and
   * requests a rescore per affected org. Runs as the owner role: enrichment is
   * platform-wide by nature and RLS would hide every tenant's findings.
   */
  private async propagate(
    kevUpdates: Array<{ cve: string; kev: boolean; kevDueDate: Date | null }>,
    epssUpdates: Array<{ cve: string; epssScore: number }>,
  ): Promise<{ findingsUpdated: number; orgsNotified: number }> {
    const byCve = new Map<string, { kev?: boolean; epssScore?: number }>();
    for (const u of kevUpdates) byCve.set(u.cve, { ...byCve.get(u.cve), kev: u.kev });
    for (const u of epssUpdates) {
      byCve.set(u.cve, { ...byCve.get(u.cve), epssScore: u.epssScore });
    }

    const touched = new Map<string, Set<string>>(); // orgId → findingIds
    for (const [cve, patch] of byCve) {
      const findings = await this.store.finding.findMany({
        where: {
          state: { in: ['open', 'triaged', 'in_progress'] },
          identifiers: { array_contains: [{ value: cve }] },
        },
        select: { id: true, orgId: true },
      });
      if (!findings.length) continue;

      await this.store.finding.updateMany({
        where: { id: { in: findings.map((f) => f.id) } },
        data: patch,
      });
      for (const f of findings) {
        if (!touched.has(f.orgId)) touched.set(f.orgId, new Set());
        touched.get(f.orgId)!.add(f.id);
      }
    }

    for (const [orgId, ids] of touched) {
      await this.bus.publish(SUBJECTS.riskRescoreRequested, orgId, { findingIds: [...ids] });
    }

    return {
      findingsUpdated: [...touched.values()].reduce((n, s) => n + s.size, 0),
      orgsNotified: touched.size,
    };
  }
}

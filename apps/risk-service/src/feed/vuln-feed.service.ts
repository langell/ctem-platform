import { Injectable, OnApplicationBootstrap, OnModuleDestroy } from '@nestjs/common';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import { FeedStore } from './feed.store';
import { advisoryAffects, advisoryToRow, type OsvAdvisory, type VulnerabilityRow } from './vuln-feed.mapper';
import {
  ghsaAffects,
  ghsaToRow,
  osvEcosystemToGhsa,
  type GhsaAdvisory,
} from './ghsa.mapper';
import { nvdToRow, type NvdCve } from './nvd.mapper';

/** Mirror entries older than this are refreshed by the background sweep. */
const MIRROR_TTL_MS = 24 * 3_600_000;
/** Pagination guard shared by OSV, GHSA and NVD listing calls. */
const MAX_PAGES = 10;
/** Packages refreshed per background sweep. */
const REFRESH_BATCH = 50;
/** NVD is rate-limited; cap per-package CVE lookups so one mirror cannot stall. */
const NVD_PER_PACKAGE = 15;
/** Recent-feed window for the NVD lastMod crawl. */
const NVD_RECENT_MS = 24 * 3_600_000;
const NVD_PAGE_SIZE = 200;
const GHSA_PAGE_SIZE = 100;
const FEED_SWEEP_MS = 6 * 3_600_000;

/**
 * Maintains the local vulnerability mirror. Packages arrive demand-driven —
 * scanners report whatever the mirror could not answer — and a background
 * sweep keeps mirrored packages from going stale. NVD and GHSA are ingested
 * on the same write path (plus a periodic recent-feed crawl) so the SCA
 * matcher can stay on the local tables. Per the build-order note in
 * docs/architecture.md: per-scan calls to a third-party API are both slow and
 * someone else's uptime problem.
 */
@Injectable()
export class VulnFeedService implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly log = rootLogger.child({ component: 'vuln-feed' });
  private staleTimer?: NodeJS.Timeout;
  private feedTimer?: NodeJS.Timeout;

  constructor(private readonly store: FeedStore) {}

  onApplicationBootstrap(): void {
    this.staleTimer = setInterval(() => void this.refreshStale(), 60 * 60_000);
    this.feedTimer = setInterval(() => void this.ingestRecentFeeds(), FEED_SWEEP_MS);
  }

  onModuleDestroy(): void {
    if (this.staleTimer) clearInterval(this.staleTimer);
    if (this.feedTimer) clearInterval(this.feedTimer);
  }

  /** Mirrors the given packages, skipping any whose sync row is still fresh. */
  async mirrorPackages(packages: Array<{ ecosystem: string; name: string }>): Promise<number> {
    let mirrored = 0;
    for (const pkg of packages) {
      const sync = await this.store.vulnPackageSync.findUnique({
        where: { ecosystem_packageName: { ecosystem: pkg.ecosystem, packageName: pkg.name } },
      });
      if (sync && Date.now() - sync.syncedAt.getTime() < MIRROR_TTL_MS) continue;

      try {
        await this.mirrorPackage(pkg.ecosystem, pkg.name);
        mirrored += 1;
      } catch (err) {
        // Leave the sync row stale/absent. A first-seen package may still hit
        // live OSV once; a package that already has a sync row is served
        // locally even while this refresh is failing.
        this.log.warn({ err, ...pkg }, 'failed to mirror package');
      }
    }
    return mirrored;
  }

  private async mirrorPackage(ecosystem: string, name: string): Promise<void> {
    const advisories = await this.fetchAdvisories(ecosystem, name);
    for (const advisory of advisories) {
      await this.writeAdvisory(advisoryToRow(advisory), advisoryAffects(advisory), 'replace');
    }

    const ghsa = await this.fetchGhsaSafe(ecosystem, name);
    for (const advisory of ghsa) {
      await this.writeAdvisory(ghsaToRow(advisory), ghsaAffects(advisory), 'fill');
    }

    const cves = collectCves(advisories, ghsa).slice(0, NVD_PER_PACKAGE);
    await this.enrichFromNvd(cves);

    const count = advisories.length + ghsa.length;
    await this.store.vulnPackageSync.upsert({
      where: { ecosystem_packageName: { ecosystem, packageName: name } },
      update: { syncedAt: new Date(), advisories: count },
      create: { ecosystem, packageName: name, syncedAt: new Date(), advisories: count },
    });

    this.log.info({ ecosystem, name, osv: advisories.length, ghsa: ghsa.length }, 'package mirrored');
  }

  /** All advisories for a package (no version filter), following OSV paging. */
  private async fetchAdvisories(ecosystem: string, name: string): Promise<OsvAdvisory[]> {
    const env = loadEnv();
    const advisories: OsvAdvisory[] = [];
    let pageToken: string | undefined;

    for (let page = 0; page < MAX_PAGES; page++) {
      const res = await fetch(`${env.OSV_API_URL}/query`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          package: { name, ecosystem },
          ...(pageToken ? { page_token: pageToken } : {}),
        }),
        signal: AbortSignal.timeout(20_000),
      });
      if (!res.ok) throw new Error(`OSV query returned ${res.status}`);

      const body = (await res.json()) as { vulns?: OsvAdvisory[]; next_page_token?: string };
      advisories.push(...(body.vulns ?? []));
      pageToken = body.next_page_token;
      if (!pageToken) break;
    }
    if (pageToken) {
      throw truncatedError('OSV', `${ecosystem}/${name}`);
    }
    return advisories;
  }

  private async fetchGhsaSafe(ecosystem: string, name: string): Promise<GhsaAdvisory[]> {
    try {
      return await this.fetchGhsa(ecosystem, name);
    } catch (err) {
      if (isTruncated(err)) throw err;
      this.log.warn({ err, ecosystem, name }, 'GHSA query failed; OSV mirror still written');
      return [];
    }
  }

  private async fetchGhsa(ecosystem: string, name: string): Promise<GhsaAdvisory[]> {
    const env = loadEnv();
    const ghsaEco = osvEcosystemToGhsa(ecosystem);
    const advisories: GhsaAdvisory[] = [];

    for (let page = 1; page <= MAX_PAGES; page++) {
      const url = new URL(`${env.GITHUB_API_URL}/advisories`);
      url.searchParams.set('ecosystem', ghsaEco);
      url.searchParams.set('affects', name);
      url.searchParams.set('type', 'reviewed');
      url.searchParams.set('per_page', String(GHSA_PAGE_SIZE));
      url.searchParams.set('page', String(page));

      const res = await fetch(url, {
        headers: ghsaHeaders(),
        signal: AbortSignal.timeout(20_000),
      });
      if (!res.ok) throw new Error(`GHSA query returned ${res.status}`);

      const items = (await res.json()) as GhsaAdvisory[];
      advisories.push(...items.filter((a) => !a.withdrawn_at));
      if (items.length < GHSA_PAGE_SIZE) break;
      if (page === MAX_PAGES) throw truncatedError('GHSA', `${ecosystem}/${name}`);
    }
    return advisories;
  }

  private async enrichFromNvd(cves: string[]): Promise<void> {
    for (const cve of cves) {
      try {
        const doc = await this.fetchNvdCve(cve);
        if (doc) await this.writeNvd(doc);
      } catch (err) {
        this.log.warn({ err, cve }, 'NVD lookup failed, continuing');
      }
    }
  }

  private async fetchNvdCve(cveId: string): Promise<NvdCve | null> {
    const env = loadEnv();
    const url = `${env.NVD_API_URL}/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
    const res = await fetch(url, { headers: nvdHeaders(), signal: AbortSignal.timeout(20_000) });
    if (!res.ok) throw new Error(`NVD query returned ${res.status}`);
    const body = (await res.json()) as { vulnerabilities?: Array<{ cve: NvdCve }> };
    return body.vulnerabilities?.[0]?.cve ?? null;
  }

  /**
   * Periodic bulk ingest of recently changed GHSA + NVD documents into the
   * shared mirror. Does not write `vuln_package_sync` — that row still means
   * "this package was observed and demand-mirrored", so first-seen packages
   * keep the one-time observe → mirror hop.
   */
  async ingestRecentFeeds(): Promise<{ ghsa: number; nvd: number }> {
    let ghsa = 0;
    let nvd = 0;
    try {
      ghsa = await this.ingestRecentGhsa();
    } catch (err) {
      this.log.warn({ err }, 'GHSA feed ingest failed');
    }
    try {
      nvd = await this.ingestRecentNvd();
    } catch (err) {
      this.log.warn({ err }, 'NVD feed ingest failed');
    }
    this.log.info({ ghsa, nvd }, 'recent feed ingest complete');
    return { ghsa, nvd };
  }

  private async ingestRecentGhsa(): Promise<number> {
    const env = loadEnv();
    const since = new Date(Date.now() - NVD_RECENT_MS);
    let ingested = 0;
    for (let page = 1; page <= MAX_PAGES; page++) {
      const url = new URL(`${env.GITHUB_API_URL}/advisories`);
      url.searchParams.set('type', 'reviewed');
      url.searchParams.set('sort', 'updated');
      url.searchParams.set('direction', 'desc');
      // GitHub date-range syntax: updated=>=ISO (see search syntax).
      url.searchParams.set('updated', `>=${since.toISOString()}`);
      url.searchParams.set('per_page', String(GHSA_PAGE_SIZE));
      url.searchParams.set('page', String(page));
      const res = await fetch(url, { headers: ghsaHeaders(), signal: AbortSignal.timeout(20_000) });
      if (!res.ok) throw new Error(`GHSA feed returned ${res.status}`);
      const items = (await res.json()) as GhsaAdvisory[];
      for (const advisory of items.filter((a) => !a.withdrawn_at && isUpdatedSince(a.updated_at, since))) {
        await this.writeAdvisory(ghsaToRow(advisory), ghsaAffects(advisory), 'fill');
        ingested += 1;
      }
      if (items.length < GHSA_PAGE_SIZE) break;
      if (page === MAX_PAGES) throw truncatedError('GHSA', 'recent feed');
    }
    return ingested;
  }

  private async ingestRecentNvd(): Promise<number> {
    const env = loadEnv();
    const end = new Date();
    const start = new Date(end.getTime() - NVD_RECENT_MS);
    let startIndex = 0;
    let ingested = 0;
    let totalResults = 0;

    for (let page = 0; page < MAX_PAGES; page++) {
      const url = new URL(`${env.NVD_API_URL}/cves/2.0`);
      url.searchParams.set('lastModStartDate', nvdDate(start));
      url.searchParams.set('lastModEndDate', nvdDate(end));
      url.searchParams.set('startIndex', String(startIndex));
      url.searchParams.set('resultsPerPage', String(NVD_PAGE_SIZE));

      const res = await fetch(url, { headers: nvdHeaders(), signal: AbortSignal.timeout(30_000) });
      if (!res.ok) throw new Error(`NVD feed returned ${res.status}`);
      const body = (await res.json()) as {
        startIndex?: number;
        resultsPerPage?: number;
        totalResults?: number;
        vulnerabilities?: Array<{ cve: NvdCve }>;
      };
      for (const item of body.vulnerabilities ?? []) {
        await this.writeNvd(item.cve);
        ingested += 1;
      }
      const pageSize = body.resultsPerPage ?? (body.vulnerabilities?.length ?? 0);
      totalResults = body.totalResults ?? totalResults;
      startIndex += pageSize;
      if (!pageSize || startIndex >= totalResults) break;
    }
    if (startIndex < totalResults) throw truncatedError('NVD', 'recent feed');
    return ingested;
  }

  /**
   * `replace` — OSV is authoritative for ranges; rewrite `affected` and the
   * package index. `fill` — NVD-style: never wipe existing OSV ranges, union
   * the package index. GHSA must use `fill` because OSV ids for GitHub vulns
   * are typically `GHSA-…`.
   */
  private async writeAdvisory(
    row: VulnerabilityRow,
    affects: Array<{ ecosystem: string; packageName: string }>,
    mode: 'replace' | 'fill',
  ): Promise<void> {
    if (mode === 'fill') {
      const existing = await this.store.vulnerability.findUnique({ where: { id: row.id } });
      if (existing && hasAffectedPayload(existing.affected)) {
        const aliases = [...new Set([...existing.aliases, ...row.aliases])];
        await this.store.$transaction([
          this.store.vulnerability.update({
            where: { id: row.id },
            data: {
              summary: existing.summary || row.summary,
              details: existing.details || row.details,
              severity: existing.cvssScore != null ? existing.severity : row.severity,
              cvssVector: existing.cvssVector ?? row.cvssVector,
              cvssScore: existing.cvssScore ?? row.cvssScore,
              publishedAt: existing.publishedAt ?? row.publishedAt,
              modifiedAt: row.modifiedAt ?? existing.modifiedAt,
              aliases,
            },
          }),
          this.store.vulnerabilityAffects.createMany({
            data: affects.map((a) => ({ vulnId: row.id, ...a })),
            skipDuplicates: true,
          }),
        ]);
        return;
      }
    }

    const { id: _id, ...update } = row;
    await this.store.$transaction([
      // Never clobber enrichment (kev, epssScore) other jobs may have written.
      this.store.vulnerability.upsert({ where: { id: row.id }, update, create: row }),
      this.store.vulnerabilityAffects.deleteMany({ where: { vulnId: row.id } }),
      this.store.vulnerabilityAffects.createMany({
        data: affects.map((a) => ({ vulnId: row.id, ...a })),
        skipDuplicates: true,
      }),
    ]);
  }

  /**
   * Upsert the NVD CVE row and overlay official CVSS onto any existing
   * advisory that aliases this CVE (typically a GHSA/OSV id). Does not
   * rewrite `affected` — NVD has CPE, not ecosystem/package ranges.
   */
  private async writeNvd(cve: NvdCve): Promise<void> {
    const row = nvdToRow(cve);
    const existing = await this.store.vulnerability.findUnique({ where: { id: row.id } });
    if (existing) {
      await this.store.vulnerability.update({
        where: { id: row.id },
        data: {
          summary: row.summary || existing.summary,
          details: row.details || existing.details,
          severity: row.cvssScore != null ? row.severity : existing.severity,
          cvssVector: row.cvssVector ?? existing.cvssVector,
          cvssScore: row.cvssScore ?? existing.cvssScore,
          publishedAt: row.publishedAt ?? existing.publishedAt,
          modifiedAt: row.modifiedAt ?? existing.modifiedAt,
          references: row.references,
          source: existing.source === 'OSV' || existing.source === 'GHSA' ? existing.source : 'NVD',
        },
      });
    } else {
      await this.store.vulnerability.create({ data: row });
    }

    if (row.cvssScore == null) return;
    const aliased = await this.store.vulnerability.findMany({
      where: { aliases: { has: row.id }, cvssScore: null },
      select: { id: true },
    });
    for (const alias of aliased) {
      await this.store.vulnerability.update({
        where: { id: alias.id },
        data: { cvssScore: row.cvssScore, cvssVector: row.cvssVector, severity: row.severity },
      });
    }
  }

  /** Background sweep: re-mirror the stalest packages so entries never expire en masse. */
  async refreshStale(): Promise<void> {
    const stale = await this.store.vulnPackageSync.findMany({
      where: { syncedAt: { lt: new Date(Date.now() - MIRROR_TTL_MS) } },
      orderBy: { syncedAt: 'asc' },
      take: REFRESH_BATCH,
    });
    if (!stale.length) return;

    this.log.info({ count: stale.length }, 'refreshing stale mirror entries');
    for (const row of stale) {
      try {
        await this.mirrorPackage(row.ecosystem, row.packageName);
      } catch (err) {
        this.log.warn({ err, package: row.packageName }, 'stale refresh failed');
      }
    }
  }
}

function hasAffectedPayload(affected: unknown): boolean {
  return Array.isArray(affected) && affected.length > 0;
}

function isUpdatedSince(updatedAt: string | undefined, since: Date): boolean {
  if (!updatedAt) return true;
  const at = new Date(updatedAt);
  return Number.isNaN(at.getTime()) || at.getTime() >= since.getTime();
}

function truncatedError(source: string, what: string): Error {
  return new Error(`${source} listing truncated at ${MAX_PAGES} pages for ${what}`);
}

function isTruncated(err: unknown): boolean {
  return err instanceof Error && err.message.includes('truncated at');
}

function collectCves(osv: OsvAdvisory[], ghsa: GhsaAdvisory[]): string[] {
  const ids = new Set<string>();
  for (const a of osv) {
    for (const id of [a.id, ...(a.aliases ?? [])]) {
      if (id.startsWith('CVE-')) ids.add(id);
    }
  }
  for (const a of ghsa) {
    if (a.cve_id?.startsWith('CVE-')) ids.add(a.cve_id);
  }
  return [...ids];
}

function ghsaHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN;
  return {
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
    'user-agent': 'ctem-platform',
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };
}

function nvdHeaders(): Record<string, string> {
  const env = loadEnv();
  return env.NVD_API_KEY ? { apiKey: env.NVD_API_KEY } : {};
}

function nvdDate(d: Date): string {
  return d.toISOString().replace('Z', '+00:00');
}

import { Injectable, OnApplicationBootstrap, OnModuleDestroy } from '@nestjs/common';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import { FeedStore } from './feed.store';
import { advisoryAffects, advisoryToRow, type OsvAdvisory } from './vuln-feed.mapper';

/** Mirror entries older than this are refreshed by the background sweep. */
const MIRROR_TTL_MS = 24 * 3_600_000;
/** OSV pagination guard — a single package should never need more. */
const MAX_PAGES = 10;
/** Packages refreshed per background sweep. */
const REFRESH_BATCH = 50;

/**
 * Maintains the local vulnerability mirror. Packages arrive demand-driven —
 * scanners report whatever the mirror could not answer — and a background
 * sweep keeps mirrored packages from going stale. Per the build-order note in
 * docs/architecture.md: per-scan calls to a third-party API are both slow and
 * someone else's uptime problem.
 */
@Injectable()
export class VulnFeedService implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly log = rootLogger.child({ component: 'vuln-feed' });
  private timer?: NodeJS.Timeout;

  constructor(private readonly store: FeedStore) {}

  onApplicationBootstrap(): void {
    this.timer = setInterval(() => void this.refreshStale(), 60 * 60_000);
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
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
        // Leave the sync row stale/absent; scanners keep falling back to live
        // OSV for this package and it will be re-observed.
        this.log.warn({ err, ...pkg }, 'failed to mirror package');
      }
    }
    return mirrored;
  }

  private async mirrorPackage(ecosystem: string, name: string): Promise<void> {
    const advisories = await this.fetchAdvisories(ecosystem, name);

    for (const advisory of advisories) {
      const row = advisoryToRow(advisory);
      const affects = advisoryAffects(advisory);
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

    await this.store.vulnPackageSync.upsert({
      where: { ecosystem_packageName: { ecosystem, packageName: name } },
      update: { syncedAt: new Date(), advisories: advisories.length },
      create: { ecosystem, packageName: name, syncedAt: new Date(), advisories: advisories.length },
    });

    this.log.info({ ecosystem, name, advisories: advisories.length }, 'package mirrored');
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
    return advisories;
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

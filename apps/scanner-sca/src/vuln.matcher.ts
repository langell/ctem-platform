import { Injectable, Optional } from '@nestjs/common';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import { Severity } from '@ctem/contracts';
import { PrismaService } from '@ctem/db';
import { versionAffected, type OsvAffected } from './osv-range';
import type { ResolvedComponent } from './sbom.parser';

export interface VulnMatch {
  id: string;
  source: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  cvssVector: string | null;
  cvssScore: number | null;
  epssScore: number | null;
  kev: boolean;
  fixedVersion?: string;
}

export interface MatchResult {
  matches: VulnMatch[];
  /** True when the local mirror answered; false means we fell back to live OSV. */
  mirrored: boolean;
}

/** A mirror entry older than this is treated as a miss and re-observed. */
const MIRROR_TTL_MS = 24 * 3_600_000;

/**
 * Matches resolved components against vulnerability intelligence.
 *
 * Local-first: if the mirror (`vulnerabilities` + `vulnerability_affects`,
 * maintained by the risk-service feed ingester) has a fresh sync row for the
 * package, matching is a pure database read. Otherwise we fall back to a live
 * OSV query and report the package as observed so the ingester mirrors it —
 * the second scan of any package never leaves the building.
 */
@Injectable()
export class VulnMatcher {
  private readonly log = rootLogger.child({ component: 'vuln-matcher' });
  private readonly kevIds = new Set<string>();
  private readonly epss = new Map<string, number>();

  /** Optional so unit tests can run the live path without a database. */
  constructor(@Optional() private readonly prisma?: PrismaService) {}

  /** Pulls KEV and EPSS once at startup; both are small and change daily. */
  async warmCache(): Promise<void> {
    const env = loadEnv();
    try {
      const res = await fetch(env.KEV_FEED_URL, { signal: AbortSignal.timeout(20_000) });
      const kev = (await res.json()) as { vulnerabilities?: Array<{ cveID: string }> };
      for (const v of kev.vulnerabilities ?? []) this.kevIds.add(v.cveID);
      this.log.info({ count: this.kevIds.size }, 'KEV catalog loaded');
    } catch (err) {
      // A cold cache degrades prioritization; it must not stop the scanner.
      this.log.warn({ err }, 'failed to load KEV catalog, continuing without it');
    }
    // TODO: page the EPSS API into this.epss, and refresh both on a timer.
  }

  async match(component: ResolvedComponent): Promise<MatchResult> {
    const local = await this.matchLocal(component);
    if (local) return { matches: local, mirrored: true };
    return { matches: await this.matchLive(component), mirrored: false };
  }

  /** Returns null when the mirror has nothing fresh for this package. */
  private async matchLocal(component: ResolvedComponent): Promise<VulnMatch[] | null> {
    if (!this.prisma || component.ecosystem === 'unknown') return null;

    try {
      const sync = await this.prisma.vulnPackageSync.findUnique({
        where: {
          ecosystem_packageName: { ecosystem: component.ecosystem, packageName: component.name },
        },
      });
      if (!sync || Date.now() - sync.syncedAt.getTime() > MIRROR_TTL_MS) return null;

      const rows = await this.prisma.vulnerabilityAffects.findMany({
        where: { ecosystem: component.ecosystem, packageName: component.name },
        include: { vulnerability: true },
      });

      return rows
        .filter((row) =>
          versionAffected(component.version, row.vulnerability.affected as OsvAffected[], {
            name: component.name,
            ecosystem: component.ecosystem,
          }),
        )
        .map((row) => this.rowToMatch(row.vulnerability, component));
    } catch (err) {
      // The mirror is an optimization; a read failure must not fail the scan.
      this.log.warn({ err, component: component.name }, 'mirror lookup failed, using live OSV');
      return null;
    }
  }

  private rowToMatch(
    row: {
      id: string;
      source: string;
      aliases: string[];
      summary: string;
      severity: string;
      cvssVector: string | null;
      cvssScore: number | null;
      epssScore: number | null;
      kev: boolean;
      affected: unknown;
    },
    component: ResolvedComponent,
  ): VulnMatch {
    const cveId = [row.id, ...row.aliases].find((a) => a.startsWith('CVE-'));
    const severity = Severity.safeParse(row.severity);
    return {
      id: row.id,
      source: row.source,
      aliases: row.aliases,
      summary: row.summary,
      severity: severity.success ? severity.data : 'medium',
      cvssVector: row.cvssVector,
      cvssScore: row.cvssScore,
      // KEV/EPSS overlay from the warm cache beats possibly-stale row values.
      epssScore: (cveId ? this.epss.get(cveId) : undefined) ?? row.epssScore,
      kev: row.kev || (cveId ? this.kevIds.has(cveId) : false),
      fixedVersion: firstFixedVersion(
        { id: row.id, affected: row.affected as OsvVuln['affected'] },
        component.ecosystem,
      ),
    };
  }

  private async matchLive(component: ResolvedComponent): Promise<VulnMatch[]> {
    const env = loadEnv();
    try {
      const res = await fetch(`${env.OSV_API_URL}/query`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          package: { name: component.name, ecosystem: component.ecosystem },
          version: component.version,
        }),
        signal: AbortSignal.timeout(15_000),
      });

      if (!res.ok) {
        this.log.warn({ status: res.status, component: component.name }, 'OSV query failed');
        return [];
      }

      const body = (await res.json()) as { vulns?: OsvVuln[] };
      return (body.vulns ?? []).map((v) => this.toMatch(v, component));
    } catch (err) {
      this.log.warn({ err, component: component.name }, 'OSV query error');
      return [];
    }
  }

  private toMatch(vuln: OsvVuln, component: ResolvedComponent): VulnMatch {
    const cvss = vuln.severity?.find((s) => s.type?.startsWith('CVSS'));
    const score = cvss ? parseCvssBaseScore(cvss.score) : null;
    const cveId = [vuln.id, ...(vuln.aliases ?? [])].find((a) => a.startsWith('CVE-'));

    return {
      id: vuln.id,
      source: vuln.id.startsWith('GHSA') ? 'GHSA' : vuln.id.startsWith('CVE') ? 'CVE' : 'OSV',
      aliases: vuln.aliases ?? [],
      summary: vuln.summary ?? vuln.details?.slice(0, 500) ?? '',
      severity: severityFromScore(score),
      cvssVector: cvss?.score ?? null,
      cvssScore: score,
      epssScore: cveId ? (this.epss.get(cveId) ?? null) : null,
      kev: cveId ? this.kevIds.has(cveId) : false,
      fixedVersion: firstFixedVersion(vuln, component.ecosystem),
    };
  }
}

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type?: string; score: string }>;
  affected?: Array<{
    package?: { ecosystem?: string };
    ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
}

function firstFixedVersion(vuln: OsvVuln, ecosystem: string): string | undefined {
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.ecosystem && affected.package.ecosystem !== ecosystem) continue;
    for (const range of affected.ranges ?? []) {
      const fixed = range.events?.find((e) => e.fixed)?.fixed;
      if (fixed) return fixed;
    }
  }
  return undefined;
}

/** OSV reports CVSS as a vector string; the base score has to be derived. */
function parseCvssBaseScore(vector: string): number | null {
  const numeric = Number(vector);
  if (!Number.isNaN(numeric)) return numeric;
  // TODO: implement full CVSS v3.1/v4.0 base score computation from the vector.
  return null;
}

function severityFromScore(score: number | null): Severity {
  if (score === null) return 'medium';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

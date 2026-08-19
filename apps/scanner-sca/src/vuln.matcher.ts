import { Injectable } from '@nestjs/common';
import { loadEnv } from '@ctem/config';
import { rootLogger } from '@ctem/observability';
import type { Severity } from '@ctem/contracts';
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

/**
 * Matches resolved components against vulnerability intelligence.
 *
 * Design note: OSV is the query API today because it is free, well-maintained
 * and covers every ecosystem we care about. The interface below is deliberately
 * feed-agnostic — the intent is to mirror OSV + NVD + GHSA into our own
 * `vulnerabilities` table and match locally, because per-scan API calls to a
 * third party are both slow and a dependency on someone else's uptime.
 */
@Injectable()
export class VulnMatcher {
  private readonly log = rootLogger.child({ component: 'vuln-matcher' });
  private readonly kevIds = new Set<string>();
  private readonly epss = new Map<string, number>();

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

  async match(component: ResolvedComponent): Promise<VulnMatch[]> {
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

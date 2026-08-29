/**
 * Pure mapping from an OSV advisory document to our `vulnerabilities` row plus
 * its package index rows. Kept free of IO so the shape logic is unit-testable.
 */
import type { Prisma } from '@ctem/db';

export interface OsvAdvisory {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  severity?: Array<{ type?: string; score: string }>;
  references?: Array<{ type?: string; url: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    versions?: string[];
    ranges?: unknown[];
  }>;
}

export interface VulnerabilityRow {
  id: string;
  source: string;
  aliases: string[];
  summary: string;
  details: string;
  severity: string;
  cvssVector: string | null;
  cvssScore: number | null;
  publishedAt: Date | null;
  modifiedAt: Date | null;
  references: Prisma.InputJsonValue;
  affected: Prisma.InputJsonValue;
}

export interface AffectsRow {
  ecosystem: string;
  packageName: string;
}

export function advisoryToRow(advisory: OsvAdvisory): VulnerabilityRow {
  const cvss = advisory.severity?.find((s) => s.type?.startsWith('CVSS'));
  const score = cvss ? parseCvssBaseScore(cvss.score) : null;

  return {
    id: advisory.id,
    source: advisory.id.startsWith('GHSA')
      ? 'GHSA'
      : advisory.id.startsWith('CVE')
        ? 'CVE'
        : 'OSV',
    aliases: advisory.aliases ?? [],
    summary: advisory.summary ?? advisory.details?.slice(0, 500) ?? '',
    details: advisory.details ?? '',
    severity: severityFromScore(score),
    cvssVector: cvss?.score ?? null,
    cvssScore: score,
    publishedAt: advisory.published ? new Date(advisory.published) : null,
    modifiedAt: advisory.modified ? new Date(advisory.modified) : null,
    references: (advisory.references ?? []) as unknown as Prisma.InputJsonValue,
    affected: (advisory.affected ?? []) as unknown as Prisma.InputJsonValue,
  };
}

/** One index row per distinct (ecosystem, package) the advisory touches. */
export function advisoryAffects(advisory: OsvAdvisory): AffectsRow[] {
  const seen = new Map<string, AffectsRow>();
  for (const entry of advisory.affected ?? []) {
    const ecosystem = entry.package?.ecosystem;
    const packageName = entry.package?.name;
    if (!ecosystem || !packageName) continue;
    seen.set(`${ecosystem}:${packageName}`, { ecosystem, packageName });
  }
  return [...seen.values()];
}

/** OSV reports CVSS as a vector string or a bare number; derive what we can. */
export function parseCvssBaseScore(vector: string): number | null {
  const numeric = Number(vector);
  if (!Number.isNaN(numeric)) return numeric;
  // TODO: full CVSS v3.1/v4.0 base-score computation from the vector.
  return null;
}

export function severityFromScore(score: number | null): string {
  if (score === null) return 'medium';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

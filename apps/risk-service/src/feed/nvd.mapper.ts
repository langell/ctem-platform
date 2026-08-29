/**
 * Pure mapping from an NVD CVE 2.0 document to our `vulnerabilities` row.
 * NVD identifies products by CPE, not ecosystem/package, so we do not invent
 * `vulnerability_affects` rows — those come from OSV/GHSA.
 */
import { severityFromScore, type VulnerabilityRow } from './vuln-feed.mapper';
import type { Prisma } from '@ctem/db';

export interface NvdCvssMetric {
  source?: string;
  type?: string;
  cvssData?: {
    baseScore?: number;
    vectorString?: string;
    baseSeverity?: string;
  };
}

export interface NvdCve {
  id: string;
  published?: string;
  lastModified?: string;
  descriptions?: Array<{ lang?: string; value?: string }>;
  metrics?: {
    cvssMetricV40?: NvdCvssMetric[];
    cvssMetricV31?: NvdCvssMetric[];
    cvssMetricV30?: NvdCvssMetric[];
    cvssMetricV2?: NvdCvssMetric[];
  };
  references?: Array<{ url?: string }>;
}

export interface NvdCvss {
  score: number;
  vector: string;
  severity: string;
}

/** Prefer newer CVSS, and NVD's Primary metric over a CNA's. */
export function pickNvdCvss(metrics: NvdCve['metrics']): NvdCvss | null {
  const groups = [
    metrics?.cvssMetricV40,
    metrics?.cvssMetricV31,
    metrics?.cvssMetricV30,
    metrics?.cvssMetricV2,
  ];
  for (const group of groups) {
    if (!group?.length) continue;
    const chosen = group.find((m) => m.type === 'Primary') ?? group[0];
    const data = chosen.cvssData;
    if (data?.baseScore == null) continue;
    return {
      score: data.baseScore,
      vector: data.vectorString ?? String(data.baseScore),
      severity: nvdSeverity(data.baseSeverity, data.baseScore),
    };
  }
  return null;
}

export function nvdToRow(cve: NvdCve): VulnerabilityRow {
  const cvss = pickNvdCvss(cve.metrics);
  const desc = cve.descriptions?.find((d) => d.lang === 'en') ?? cve.descriptions?.[0];
  const text = desc?.value ?? '';

  return {
    id: cve.id,
    source: 'NVD',
    aliases: [],
    summary: text.slice(0, 500),
    details: text,
    severity: cvss?.severity ?? severityFromScore(cvss?.score ?? null),
    cvssVector: cvss?.vector ?? null,
    cvssScore: cvss?.score ?? null,
    publishedAt: cve.published ? new Date(cve.published) : null,
    modifiedAt: cve.lastModified ? new Date(cve.lastModified) : null,
    references: (cve.references ?? [])
      .filter((r) => r.url)
      .map((r) => ({ url: r.url })) as unknown as Prisma.InputJsonValue,
    affected: [],
  };
}

function nvdSeverity(raw: string | undefined, score: number): string {
  if (!raw) return severityFromScore(score);
  const lower = raw.toLowerCase();
  if (lower === 'none') return 'info';
  return lower;
}

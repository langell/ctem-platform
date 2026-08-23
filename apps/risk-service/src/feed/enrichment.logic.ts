/**
 * Pure decision logic for threat-intel enrichment: given mirrored advisories
 * and the latest KEV/EPSS data, compute exactly which rows change. IO-free so
 * the diffing rules are unit-testable.
 */

export interface VulnIntelRow {
  id: string;
  aliases: string[];
  kev: boolean;
  kevDueDate: Date | null;
  epssScore: number | null;
}

export interface KevEntry {
  dueDate: Date | null;
}

export interface KevUpdate {
  id: string;
  cve: string;
  kev: boolean;
  kevDueDate: Date | null;
}

export interface EpssUpdate {
  id: string;
  cve: string;
  epssScore: number;
  epssPercentile: number | null;
}

/** The CVE identity of an advisory: its own id, or its first CVE alias. */
export function resolveCve(row: { id: string; aliases: string[] }): string | null {
  return [row.id, ...row.aliases].find((a) => a.startsWith('CVE-')) ?? null;
}

/** Rows whose KEV membership (or due date) differs from the catalog. */
export function computeKevUpdates(
  rows: VulnIntelRow[],
  kevCatalog: Map<string, KevEntry>,
): KevUpdate[] {
  const updates: KevUpdate[] = [];
  for (const row of rows) {
    const cve = resolveCve(row);
    if (!cve) continue;
    const entry = kevCatalog.get(cve);
    const kev = entry !== undefined;
    const dueDate = entry?.dueDate ?? null;
    if (kev !== row.kev || (kev && dueDate?.getTime() !== row.kevDueDate?.getTime())) {
      updates.push({ id: row.id, cve, kev, kevDueDate: dueDate });
    }
  }
  return updates;
}

/** Rows whose EPSS score moved by more than the noise threshold. */
export function computeEpssUpdates(
  rows: VulnIntelRow[],
  scores: Map<string, { epss: number; percentile: number | null }>,
  threshold = 0.001,
): EpssUpdate[] {
  const updates: EpssUpdate[] = [];
  for (const row of rows) {
    const cve = resolveCve(row);
    if (!cve) continue;
    const latest = scores.get(cve);
    if (!latest) continue;
    if (row.epssScore === null || Math.abs(latest.epss - row.epssScore) > threshold) {
      updates.push({ id: row.id, cve, epssScore: latest.epss, epssPercentile: latest.percentile });
    }
  }
  return updates;
}

export function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

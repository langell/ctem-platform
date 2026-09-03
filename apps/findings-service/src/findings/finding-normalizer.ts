import { Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import type { RawFinding } from '@ctem/contracts';

/** Persist shape after same-identity hits in one scan have been unioned. */
export type CollapsedFinding = {
  fingerprint: string;
  finding: RawFinding;
  location: Record<string, unknown>;
  evidence: Record<string, unknown>;
};

/**
 * Normalization is where a platform earns trust. Four scanners will report the
 * same CVE in the same package; the user should see one finding with four
 * sources, not four duplicates.
 */
@Injectable()
export class FindingNormalizer {
  /**
   * Fingerprint deliberately excludes line numbers for dependency findings —
   * a lockfile reorder must not resurrect a finding the team already triaged.
   * For code findings it includes the path but not the line, and leans on the
   * rule id, so a diff above the match does not create a duplicate.
   *
   * SCA identity is (asset, sca, vuln, purl). Lockfile path is not part of the
   * key — a monorepo must not mint two tickets for the same CVE.
   */
  fingerprint(assetId: string, finding: RawFinding): string {
    // IaC identity is (asset, iac, rule, path, resource address). Two buckets
    // in one file must not collapse, and this key must not collide with SCA
    // (asset, sca, vuln, purl) or SAST (asset, sast, id, path).
    if (finding.scannerType === 'iac') {
      const ruleId =
        finding.identifiers.find((i) => i.system.toLowerCase() === 'rule')?.value ?? finding.externalId;
      return createHash('sha256')
        .update([assetId, 'iac', ruleId, finding.location.path ?? '', finding.location.resource ?? ''].join('|'))
        .digest('hex');
    }

    const parts: string[] = [assetId, finding.scannerType];

    const cve = finding.identifiers.find((i) => /^(cve|ghsa|osv)$/i.test(i.system));
    if (cve) {
      parts.push(cve.value.toUpperCase());
    } else {
      parts.push(finding.externalId);
    }

    switch (finding.scannerType) {
      case 'sca':
      case 'container':
        parts.push(finding.location.purl ?? `${finding.location.packageName}@${finding.location.packageVersion}`);
        break;
      case 'sast':
      case 'secrets':
        parts.push(finding.location.path ?? '');
        break;
      case 'asm':
      case 'cloud_posture':
        parts.push(finding.location.resource ?? finding.location.url ?? String(finding.location.port ?? ''));
        break;
    }

    return createHash('sha256').update(parts.join('|')).digest('hex');
  }

  /**
   * Component-level lockfile dedupe keeps one hit per (package, manifest).
   * Persist would otherwise overwrite location/evidence on the second upsert
   * of the same fingerprint. Collapse those hits here and union the paths.
   */
  collapseScan(assetId: string, findings: RawFinding[]): CollapsedFinding[] {
    const byFingerprint = new Map<string, CollapsedFinding>();

    for (const finding of findings) {
      const fingerprint = this.fingerprint(assetId, finding);
      const incoming: CollapsedFinding = {
        fingerprint,
        finding,
        location: { ...(finding.location as Record<string, unknown>) },
        evidence: { ...(finding.evidence as Record<string, unknown>) },
      };
      const existing = byFingerprint.get(fingerprint);
      if (!existing) {
        byFingerprint.set(fingerprint, incoming);
        continue;
      }
      byFingerprint.set(fingerprint, {
        fingerprint,
        finding: existing.finding,
        location: unionLocation(existing.location, incoming.location),
        evidence: unionEvidence(existing.evidence, incoming.evidence),
      });
    }

    return [...byFingerprint.values()];
  }

  /**
   * Scanner severities disagree constantly. Prefer CVSS when present, fall back
   * to the scanner's own label, and never let a scanner claim `critical` on a
   * finding with a CVSS below 9.
   */
  reconcileSeverity(finding: RawFinding): RawFinding['severity'] {
    const score = finding.cvssScore;
    if (score === null || score === undefined) return finding.severity;
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    if (score > 0) return 'low';
    return 'info';
  }
}

function unionLocation(
  existing: Record<string, unknown>,
  incoming: Record<string, unknown>,
): Record<string, unknown> {
  const path = unionLockfilePaths(existing.path, incoming.path);
  return path === undefined ? existing : { ...existing, path };
}

function unionEvidence(
  existing: Record<string, unknown>,
  incoming: Record<string, unknown>,
): Record<string, unknown> {
  const dependencyPath = unionDependencyPaths(existing.dependencyPath, incoming.dependencyPath);
  return dependencyPath === undefined ? existing : { ...existing, dependencyPath };
}

function unionLockfilePaths(a: unknown, b: unknown): string | string[] | undefined {
  const unique = [...new Set([...lockfilePaths(a), ...lockfilePaths(b)])].sort();
  if (unique.length === 0) return undefined;
  return unique.length === 1 ? unique[0] : unique;
}

function unionDependencyPaths(a: unknown, b: unknown): string[] | string[][] | undefined {
  const seen = new Set<string>();
  const out: string[][] = [];
  for (const path of [...dependencyPaths(a), ...dependencyPaths(b)]) {
    const key = JSON.stringify(path);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(path);
  }
  if (out.length === 0) return undefined;
  return out.length === 1 ? out[0] : out;
}

function lockfilePaths(value: unknown): string[] {
  if (typeof value === 'string' && value.length > 0) return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string' && v.length > 0);
  return [];
}

function dependencyPaths(value: unknown): string[][] {
  if (!Array.isArray(value) || value.length === 0) return [];
  if (value.every((v) => typeof v === 'string')) return [value as string[]];
  return value.filter((v): v is string[] => Array.isArray(v) && v.every((s) => typeof s === 'string'));
}

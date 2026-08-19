import { Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import type { RawFinding } from '@ctem/contracts';

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
   */
  fingerprint(assetId: string, finding: RawFinding): string {
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
      case 'iac':
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

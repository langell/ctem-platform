/**
 * Pure mapping from a GitHub Security Advisory to our `vulnerabilities` row
 * plus OSV-shaped `affected` ranges the SCA matcher already understands.
 */
import { advisoryAffects, advisoryToRow, severityFromScore, type AffectsRow, type VulnerabilityRow } from './vuln-feed.mapper';

/** GitHub's ecosystem names → OSV's, so the package index matches SBOM purls. */
const GHSA_TO_OSV: Record<string, string> = {
  npm: 'npm',
  pip: 'PyPI',
  maven: 'Maven',
  nuget: 'NuGet',
  composer: 'Packagist',
  go: 'Go',
  rust: 'crates.io',
  rubygems: 'RubyGems',
  erlang: 'Hex',
  pub: 'Pub',
  swift: 'SwiftURL',
  actions: 'GitHub Actions',
};

const OSV_TO_GHSA: Record<string, string> = {
  npm: 'npm',
  PyPI: 'pip',
  Maven: 'maven',
  NuGet: 'nuget',
  Packagist: 'composer',
  Go: 'go',
  'crates.io': 'rust',
  RubyGems: 'rubygems',
  Hex: 'erlang',
  Pub: 'pub',
  SwiftURL: 'swift',
  'GitHub Actions': 'actions',
};

export interface GhsaAdvisory {
  ghsa_id: string;
  cve_id?: string | null;
  summary?: string;
  description?: string;
  severity?: string;
  published_at?: string;
  updated_at?: string;
  withdrawn_at?: string | null;
  cvss?: { score?: number | null; vector_string?: string | null } | null;
  references?: string[];
  vulnerabilities?: Array<{
    package?: { ecosystem?: string; name?: string };
    vulnerable_version_range?: string | null;
    first_patched_version?: { identifier?: string } | null;
  }>;
}

export function ghsaEcosystemToOsv(ecosystem: string | undefined): string | undefined {
  if (!ecosystem) return undefined;
  return GHSA_TO_OSV[ecosystem.toLowerCase()] ?? ecosystem;
}

export function osvEcosystemToGhsa(ecosystem: string): string {
  return OSV_TO_GHSA[ecosystem] ?? ecosystem.toLowerCase();
}

export function ghsaToRow(advisory: GhsaAdvisory): VulnerabilityRow {
  const affected = (advisory.vulnerabilities ?? []).map((v) => ({
    package: {
      name: v.package?.name,
      ecosystem: ghsaEcosystemToOsv(v.package?.ecosystem),
    },
    ...ghsaRangeToOsv(v.vulnerable_version_range, v.first_patched_version?.identifier),
  }));

  const row = advisoryToRow({
    id: advisory.ghsa_id,
    aliases: advisory.cve_id ? [advisory.cve_id] : [],
    summary: advisory.summary,
    details: advisory.description,
    published: advisory.published_at,
    modified: advisory.updated_at,
    severity:
      advisory.cvss?.score != null ? [{ type: 'CVSS_V3', score: String(advisory.cvss.score) }] : undefined,
    references: (advisory.references ?? []).map((url) => ({ url })),
    affected,
  });

  if (advisory.cvss?.vector_string) row.cvssVector = advisory.cvss.vector_string;
  if (advisory.cvss?.score != null) {
    row.cvssScore = advisory.cvss.score;
    row.severity = severityFromScore(advisory.cvss.score);
  } else if (advisory.severity) {
    row.severity = advisory.severity.toLowerCase();
  }
  return row;
}

export function ghsaAffects(advisory: GhsaAdvisory): AffectsRow[] {
  return advisoryAffects({
    id: advisory.ghsa_id,
    affected: (advisory.vulnerabilities ?? []).map((v) => ({
      package: {
        name: v.package?.name,
        ecosystem: ghsaEcosystemToOsv(v.package?.ecosystem),
      },
    })),
  });
}

export interface OsvRangeShape {
  versions?: string[];
  ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string; last_affected?: string }> }>;
}

/** Converts a GitHub version range (`>= 1.0.0, < 1.2.3`) into OSV events. */
export function ghsaRangeToOsv(range: string | null | undefined, patched?: string | null): OsvRangeShape {
  if (!range?.trim()) {
    return {
      ranges: [
        {
          type: 'SEMVER',
          events: patched ? [{ introduced: '0' }, { fixed: patched }] : [{ introduced: '0' }],
        },
      ],
    };
  }

  let introduced = '0';
  let fixed: string | undefined;
  let lastAffected: string | undefined;
  let exact: string | undefined;

  for (const part of range.split(',').map((p) => p.trim()).filter(Boolean)) {
    const parsed = parseConstraint(part);
    if (!parsed) continue;
    switch (parsed.op) {
      case '=':
        exact = parsed.version;
        break;
      case '>=':
        introduced = parsed.version;
        break;
      case '>':
        // OSV `introduced` is inclusive; this is the closest lossless mapping.
        introduced = parsed.version;
        break;
      case '<':
        fixed = parsed.version;
        break;
      case '<=':
        lastAffected = parsed.version;
        break;
    }
  }

  if (exact && !fixed && !lastAffected && introduced === '0') {
    return { versions: [exact] };
  }
  if (!fixed && !lastAffected && patched) fixed = patched;

  const events: Array<{ introduced?: string; fixed?: string; last_affected?: string }> = [{ introduced }];
  if (fixed) events.push({ fixed });
  else if (lastAffected) events.push({ last_affected: lastAffected });
  return { ranges: [{ type: 'SEMVER', events }] };
}

function parseConstraint(part: string): { op: string; version: string } | null {
  const m = /^(>=|<=|>|<|==|=)\s*(.+)$/.exec(part);
  if (m) return { op: m[1] === '==' ? '=' : m[1], version: m[2].trim() };
  if (/^[vV]?\d/.test(part)) return { op: '=', version: part };
  return null;
}

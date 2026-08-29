import { describe, expect, it } from 'vitest';
import {
  ghsaAffects,
  ghsaEcosystemToOsv,
  ghsaRangeToOsv,
  ghsaToRow,
  osvEcosystemToGhsa,
} from './ghsa.mapper';

const advisory = {
  ghsa_id: 'GHSA-hrpp-h998-j3pp',
  cve_id: 'CVE-2022-24999',
  summary: 'qs vulnerable to prototype poisoning',
  description: 'long details…',
  severity: 'high',
  published_at: '2022-11-26T00:00:31Z',
  updated_at: '2023-01-23T18:29:00Z',
  cvss: { score: 7.5, vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' },
  references: ['https://example.test/advisory'],
  vulnerabilities: [
    {
      package: { ecosystem: 'npm', name: 'qs' },
      vulnerable_version_range: '>= 6.8.0, < 6.8.3',
      first_patched_version: { identifier: '6.8.3' },
    },
    {
      package: { ecosystem: 'pip', name: 'qs' },
      vulnerable_version_range: '< 6.7.3',
      first_patched_version: { identifier: '6.7.3' },
    },
  ],
};

describe('ghsaToRow', () => {
  it('maps identity, official CVSS vector and aliases', () => {
    const row = ghsaToRow(advisory);
    expect(row).toMatchObject({
      id: 'GHSA-hrpp-h998-j3pp',
      source: 'GHSA',
      aliases: ['CVE-2022-24999'],
      severity: 'high',
      cvssScore: 7.5,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    });
    expect(row.publishedAt?.getUTCFullYear()).toBe(2022);
  });

  it('falls back to GitHub severity when CVSS is absent', () => {
    const row = ghsaToRow({
      ghsa_id: 'GHSA-xxxx-yyyy-zzzz',
      severity: 'CRITICAL',
      summary: 'no cvss',
    });
    expect(row.severity).toBe('critical');
    expect(row.cvssScore).toBeNull();
  });
});

describe('ghsaAffects', () => {
  it('indexes OSV ecosystem names, not GitHub\'s', () => {
    expect(ghsaAffects(advisory)).toEqual([
      { ecosystem: 'npm', packageName: 'qs' },
      { ecosystem: 'PyPI', packageName: 'qs' },
    ]);
  });
});

describe('ecosystem mapping', () => {
  it('round-trips the ecosystems the SBOM parser emits', () => {
    expect(ghsaEcosystemToOsv('pip')).toBe('PyPI');
    expect(ghsaEcosystemToOsv('PIP')).toBe('PyPI');
    expect(osvEcosystemToGhsa('PyPI')).toBe('pip');
    expect(osvEcosystemToGhsa('crates.io')).toBe('rust');
  });
});

describe('ghsaRangeToOsv', () => {
  it('maps an exclusive upper bound to a fixed event', () => {
    expect(ghsaRangeToOsv('< 6.7.3')).toEqual({
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '6.7.3' }] }],
    });
  });

  it('maps a bounded interval', () => {
    expect(ghsaRangeToOsv('>= 6.8.0, < 6.8.3')).toEqual({
      ranges: [{ type: 'SEMVER', events: [{ introduced: '6.8.0' }, { fixed: '6.8.3' }] }],
    });
  });

  it('maps an inclusive upper bound to last_affected', () => {
    expect(ghsaRangeToOsv('<= 1.0.0')).toEqual({
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { last_affected: '1.0.0' }] }],
    });
  });

  it('maps an exact version to the enumerated list', () => {
    expect(ghsaRangeToOsv('= 1.2.3')).toEqual({ versions: ['1.2.3'] });
  });

  it('uses first_patched_version when the range has no upper bound', () => {
    expect(ghsaRangeToOsv('>= 1.0.0', '1.4.2')).toEqual({
      ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.4.2' }] }],
    });
  });
});

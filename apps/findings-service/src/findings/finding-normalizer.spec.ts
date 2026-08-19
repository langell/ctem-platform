import { describe, expect, it } from 'vitest';
import type { RawFinding } from '@ctem/contracts';
import { FindingNormalizer } from './finding-normalizer';

const normalizer = new FindingNormalizer();

function raw(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    externalId: 'OSV-1',
    scannerType: 'sca',
    scannerName: 'ctem-sca',
    title: 'test',
    description: '',
    severity: 'medium',
    identifiers: [{ system: 'CVE', value: 'CVE-2024-0001' }],
    cvssVector: null,
    cvssScore: null,
    epssScore: null,
    kev: false,
    location: { purl: 'pkg:npm/express@4.17.1' },
    fix: { available: false },
    evidence: {},
    raw: {},
    ...overrides,
  } as RawFinding;
}

describe('FindingNormalizer.fingerprint', () => {
  it('is stable across scans of the same asset, package and CVE', () => {
    const a = normalizer.fingerprint('asset-1', raw());
    const b = normalizer.fingerprint('asset-1', raw({ externalId: 'GHSA-xyz' }));
    // Same CVE identifier, so the scanner's own id must not change the result.
    expect(a).toBe(b);
  });

  it('separates the same CVE on different assets', () => {
    expect(normalizer.fingerprint('asset-1', raw())).not.toBe(
      normalizer.fingerprint('asset-2', raw()),
    );
  });

  it('separates the same CVE in different packages', () => {
    const other = raw({ location: { purl: 'pkg:npm/lodash@4.17.20' } });
    expect(normalizer.fingerprint('asset-1', raw())).not.toBe(
      normalizer.fingerprint('asset-1', other),
    );
  });

  it('ignores line numbers for code findings so a diff above the match is not a new finding', () => {
    const base = raw({
      scannerType: 'sast',
      identifiers: [{ system: 'rule', value: 'ctem.sql-injection' }],
      location: { path: 'src/db.ts', startLine: 10 },
    });
    const moved = raw({
      scannerType: 'sast',
      identifiers: [{ system: 'rule', value: 'ctem.sql-injection' }],
      location: { path: 'src/db.ts', startLine: 42 },
    });
    expect(normalizer.fingerprint('asset-1', base)).toBe(normalizer.fingerprint('asset-1', moved));
  });
});

describe('FindingNormalizer.reconcileSeverity', () => {
  it('trusts CVSS over the scanner label', () => {
    expect(normalizer.reconcileSeverity(raw({ severity: 'low', cvssScore: 9.8 }))).toBe('critical');
    expect(normalizer.reconcileSeverity(raw({ severity: 'critical', cvssScore: 5.1 }))).toBe('medium');
  });

  it('falls back to the scanner label when there is no CVSS', () => {
    expect(normalizer.reconcileSeverity(raw({ severity: 'high' }))).toBe('high');
  });
});

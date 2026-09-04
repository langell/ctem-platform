import { createHash } from 'node:crypto';
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

  it('is (asset, sca, vuln, purl) and does not include lockfile path', () => {
    const expected = createHash('sha256')
      .update(['asset-1', 'sca', 'CVE-2024-0001', 'pkg:npm/express@4.17.1'].join('|'))
      .digest('hex');
    const fromA = normalizer.fingerprint(
      'asset-1',
      raw({ location: { purl: 'pkg:npm/express@4.17.1', path: 'app-a/package-lock.json' } }),
    );
    const fromB = normalizer.fingerprint(
      'asset-1',
      raw({ location: { purl: 'pkg:npm/express@4.17.1', path: 'app-b/package-lock.json' } }),
    );
    expect(fromA).toBe(expected);
    expect(fromB).toBe(expected);
  });

  it('does not collide a SAST fingerprint with SCA (asset, sca, vuln, purl)', () => {
    const sca = raw({
      scannerType: 'sca',
      identifiers: [{ system: 'CVE', value: 'CVE-2024-0001' }],
      location: { purl: 'pkg:npm/express@4.17.1' },
    });
    const sast = raw({
      scannerType: 'sast',
      externalId: 'CVE-2024-0001',
      identifiers: [{ system: 'CVE', value: 'CVE-2024-0001' }],
      location: { path: 'src/db.ts', purl: 'pkg:npm/express@4.17.1' },
    });
    const scaFp = normalizer.fingerprint('asset-1', sca);
    const sastFp = normalizer.fingerprint('asset-1', sast);
    expect(scaFp).toBe(
      createHash('sha256')
        .update(['asset-1', 'sca', 'CVE-2024-0001', 'pkg:npm/express@4.17.1'].join('|'))
        .digest('hex'),
    );
    expect(sastFp).not.toBe(scaFp);
  });

  it('keeps two IaC resources in one file as distinct fingerprints (rule + path + address)', () => {
    const bucketA = raw({
      scannerType: 'iac',
      scannerName: 'ctem-iac',
      externalId: 'ctem.iac.s3-public:s3.tf:aws_s3_bucket.logs',
      identifiers: [{ system: 'rule', value: 'ctem.iac.s3-public' }],
      location: { path: 's3.tf', resource: 'aws_s3_bucket.logs' },
    });
    const bucketB = raw({
      scannerType: 'iac',
      scannerName: 'ctem-iac',
      externalId: 'ctem.iac.s3-public:s3.tf:aws_s3_bucket.assets',
      identifiers: [{ system: 'rule', value: 'ctem.iac.s3-public' }],
      location: { path: 's3.tf', resource: 'aws_s3_bucket.assets' },
    });
    const fpA = normalizer.fingerprint('asset-1', bucketA);
    const fpB = normalizer.fingerprint('asset-1', bucketB);
    expect(fpA).toBe(
      createHash('sha256')
        .update(['asset-1', 'iac', 'ctem.iac.s3-public', 's3.tf', 'aws_s3_bucket.logs'].join('|'))
        .digest('hex'),
    );
    expect(fpA).not.toBe(fpB);
    expect(normalizer.collapseScan('asset-1', [bucketA, bucketB])).toHaveLength(2);
  });

  it('does not collide an IaC fingerprint with SCA (asset, sca, vuln, purl) or SAST', () => {
    const sca = raw({
      scannerType: 'sca',
      identifiers: [{ system: 'CVE', value: 'CVE-2024-0001' }],
      location: { purl: 'pkg:npm/express@4.17.1' },
    });
    const sast = raw({
      scannerType: 'sast',
      externalId: 'ctem.iac.s3-public',
      identifiers: [{ system: 'rule', value: 'ctem.iac.s3-public' }],
      location: { path: 's3.tf', resource: 'aws_s3_bucket.logs' },
    });
    const iac = raw({
      scannerType: 'iac',
      externalId: 'ctem.iac.s3-public',
      identifiers: [{ system: 'rule', value: 'ctem.iac.s3-public' }],
      location: { path: 's3.tf', resource: 'aws_s3_bucket.logs', purl: 'pkg:npm/express@4.17.1' },
    });
    const scaFp = normalizer.fingerprint('asset-1', sca);
    const sastFp = normalizer.fingerprint('asset-1', sast);
    const iacFp = normalizer.fingerprint('asset-1', iac);
    expect(scaFp).toBe(
      createHash('sha256')
        .update(['asset-1', 'sca', 'CVE-2024-0001', 'pkg:npm/express@4.17.1'].join('|'))
        .digest('hex'),
    );
    expect(iacFp).not.toBe(scaFp);
    expect(iacFp).not.toBe(sastFp);
    expect(sastFp).not.toBe(scaFp);
  });

  it('is (asset, container, vuln, purl, layer) so base vs app layer stay distinct', () => {
    const base = raw({
      scannerType: 'container',
      scannerName: 'ctem-container',
      identifiers: [{ system: 'CVE', value: 'CVE-2024-0001' }],
      location: {
        purl: 'pkg:apk/openssl@1.1.1w',
        packageName: 'openssl',
        packageVersion: '1.1.1w',
        imageLayer: `sha256:${'b'.repeat(64)}`,
      },
    });
    const app = raw({
      scannerType: 'container',
      scannerName: 'ctem-container',
      identifiers: [{ system: 'CVE', value: 'CVE-2024-0001' }],
      location: {
        purl: 'pkg:npm/lodash@4.17.21',
        packageName: 'lodash',
        packageVersion: '4.17.21',
        imageLayer: `sha256:${'c'.repeat(64)}`,
      },
    });
    const samePkgOtherLayer = raw({
      scannerType: 'container',
      identifiers: [{ system: 'CVE', value: 'CVE-2024-0001' }],
      location: {
        purl: 'pkg:apk/openssl@1.1.1w',
        imageLayer: `sha256:${'c'.repeat(64)}`,
      },
    });
    const baseFp = normalizer.fingerprint('asset-1', base);
    const appFp = normalizer.fingerprint('asset-1', app);
    expect(baseFp).toBe(
      createHash('sha256')
        .update(
          ['asset-1', 'container', 'CVE-2024-0001', 'pkg:apk/openssl@1.1.1w', `sha256:${'b'.repeat(64)}`].join('|'),
        )
        .digest('hex'),
    );
    expect(baseFp).not.toBe(appFp);
    expect(baseFp).not.toBe(normalizer.fingerprint('asset-1', samePkgOtherLayer));

    const scaFp = normalizer.fingerprint(
      'asset-1',
      raw({
        scannerType: 'sca',
        identifiers: [{ system: 'CVE', value: 'CVE-2024-0001' }],
        location: { purl: 'pkg:apk/openssl@1.1.1w' },
      }),
    );
    const sastFp = normalizer.fingerprint(
      'asset-1',
      raw({
        scannerType: 'sast',
        identifiers: [{ system: 'CVE', value: 'CVE-2024-0001' }],
        location: { path: 'src/db.ts', purl: 'pkg:apk/openssl@1.1.1w' },
      }),
    );
    const iacFp = normalizer.fingerprint(
      'asset-1',
      raw({
        scannerType: 'iac',
        identifiers: [{ system: 'rule', value: 'ctem.iac.s3-public' }],
        location: { path: 's3.tf', resource: 'aws_s3_bucket.logs', purl: 'pkg:apk/openssl@1.1.1w' },
      }),
    );
    expect(baseFp).not.toBe(scaFp);
    expect(baseFp).not.toBe(sastFp);
    expect(baseFp).not.toBe(iacFp);
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

describe('FindingNormalizer.collapseScan', () => {
  const lodashA = raw({
    location: { purl: 'pkg:npm/lodash@4.17.21', path: 'app-a/package-lock.json' },
    evidence: { direct: true, dependencyPath: ['lodash'] },
  });
  const lodashB = raw({
    location: { purl: 'pkg:npm/lodash@4.17.21', path: 'app-b/package-lock.json' },
    evidence: { direct: false, dependencyPath: ['express', 'lodash'] },
  });
  const qs = raw({
    location: { purl: 'pkg:npm/qs@6.5.2', path: 'app-a/package-lock.json' },
    evidence: { direct: false, dependencyPath: ['express', 'qs'] },
  });

  it('unions lockfile path and dependencyPath for the same purl in one scan', () => {
    const collapsed = normalizer.collapseScan('asset-1', [lodashA, lodashB]);
    expect(collapsed).toHaveLength(1);
    expect(collapsed[0].location.path).toEqual(['app-a/package-lock.json', 'app-b/package-lock.json']);
    expect(collapsed[0].evidence.dependencyPath).toEqual([
      ['lodash'],
      ['express', 'lodash'],
    ]);
    expect(collapsed[0].fingerprint).toBe(normalizer.fingerprint('asset-1', lodashA));
    expect(collapsed[0].fingerprint).toBe(normalizer.fingerprint('asset-1', lodashB));
  });

  it('keeps different purls as two findings', () => {
    const collapsed = normalizer.collapseScan('asset-1', [lodashA, qs]);
    expect(collapsed).toHaveLength(2);
    const purls = collapsed.map((row) => row.location.purl).sort();
    expect(purls).toEqual(['pkg:npm/lodash@4.17.21', 'pkg:npm/qs@6.5.2']);
  });
});

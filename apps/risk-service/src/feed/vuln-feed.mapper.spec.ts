import { describe, expect, it } from 'vitest';
import { advisoryAffects, advisoryToRow } from './vuln-feed.mapper';

const advisory = {
  id: 'GHSA-hrpp-h998-j3pp',
  aliases: ['CVE-2022-24999'],
  summary: 'qs vulnerable to prototype poisoning',
  details: 'long details…',
  published: '2022-11-26T00:00:31Z',
  modified: '2023-01-23T18:29:00Z',
  severity: [{ type: 'CVSS_V3', score: '7.5' }],
  references: [{ type: 'ADVISORY', url: 'https://example.test/advisory' }],
  affected: [
    {
      package: { name: 'qs', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '6.7.0' }, { fixed: '6.7.3' }] }],
    },
    {
      package: { name: 'qs', ecosystem: 'npm' }, // duplicate package, second range
      ranges: [{ type: 'SEMVER', events: [{ introduced: '6.8.0' }, { fixed: '6.8.3' }] }],
    },
    {
      package: { name: 'express', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.3' }] }],
    },
  ],
};

describe('advisoryToRow', () => {
  it('maps identity, severity and timestamps', () => {
    const row = advisoryToRow(advisory);
    expect(row).toMatchObject({
      id: 'GHSA-hrpp-h998-j3pp',
      source: 'GHSA',
      aliases: ['CVE-2022-24999'],
      severity: 'high',
      cvssScore: 7.5,
    });
    expect(row.publishedAt?.getUTCFullYear()).toBe(2022);
    expect(row.affected).toHaveLength(3);
  });

  it('defaults severity to medium when no CVSS is reported', () => {
    const row = advisoryToRow({ id: 'OSV-2020-1', details: 'd' });
    expect(row.severity).toBe('medium');
    expect(row.cvssScore).toBeNull();
    expect(row.source).toBe('OSV');
  });
});

describe('advisoryAffects', () => {
  it('produces one index row per distinct package', () => {
    expect(advisoryAffects(advisory)).toEqual([
      { ecosystem: 'npm', packageName: 'qs' },
      { ecosystem: 'npm', packageName: 'express' },
    ]);
  });

  it('skips entries without package identity', () => {
    expect(advisoryAffects({ id: 'X', affected: [{ ranges: [] }] })).toEqual([]);
  });
});

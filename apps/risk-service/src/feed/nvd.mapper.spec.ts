import { describe, expect, it } from 'vitest';
import { nvdToRow, pickNvdCvss, type NvdCve } from './nvd.mapper';

const cve: NvdCve = {
  id: 'CVE-2021-44228',
  published: '2021-12-10T10:15:09.143',
  lastModified: '2025-10-27T20:19:19.643',
  descriptions: [
    { lang: 'es', value: 'traducción' },
    { lang: 'en', value: 'Apache Log4j2 JNDI lookup.' },
  ],
  metrics: {
    cvssMetricV2: [
      { type: 'Primary', cvssData: { baseScore: 9.3, vectorString: 'AV:N/AC:M/Au:N/C:C/I:C/A:C' } },
    ],
    cvssMetricV31: [
      {
        type: 'Secondary',
        cvssData: { baseScore: 8.1, vectorString: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', baseSeverity: 'HIGH' },
      },
      {
        type: 'Primary',
        cvssData: {
          baseScore: 10.0,
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
          baseSeverity: 'CRITICAL',
        },
      },
    ],
  },
  references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' }],
};

describe('pickNvdCvss', () => {
  it('prefers v3.1 Primary over v3.1 Secondary and over v2', () => {
    expect(pickNvdCvss(cve.metrics)).toEqual({
      score: 10.0,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      severity: 'critical',
    });
  });

  it('falls back to v2 when no v3 is present', () => {
    expect(pickNvdCvss({ cvssMetricV2: cve.metrics!.cvssMetricV2 })).toMatchObject({
      score: 9.3,
    });
  });

  it('returns null when NVD has not scored the CVE yet', () => {
    expect(pickNvdCvss({})).toBeNull();
  });
});

describe('nvdToRow', () => {
  it('maps identity, English description and official CVSS', () => {
    const row = nvdToRow(cve);
    expect(row).toMatchObject({
      id: 'CVE-2021-44228',
      source: 'NVD',
      aliases: [],
      summary: 'Apache Log4j2 JNDI lookup.',
      severity: 'critical',
      cvssScore: 10.0,
    });
    expect(row.affected).toEqual([]);
    expect(row.publishedAt?.getUTCFullYear()).toBe(2021);
  });

  it('defaults severity when metrics are missing', () => {
    const row = nvdToRow({ id: 'CVE-2099-0001', descriptions: [{ lang: 'en', value: 'unscored' }] });
    expect(row.severity).toBe('medium');
    expect(row.cvssScore).toBeNull();
  });
});

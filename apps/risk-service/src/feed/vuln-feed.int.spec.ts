import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { appClient, ownerClient, uniqueSlug } from '@ctem/testing';
import type { PrismaClient } from '@ctem/db';
import { FeedStore } from './feed.store';
import { VulnFeedService } from './vuln-feed.service';

/**
 * The mirror write path against the real database: OSV (stubbed) → upserts as
 * the owner role, plus proof that the app role can read but never write the
 * shared intelligence tables.
 */
describe('VulnFeedService (integration)', () => {
  const pkg = uniqueSlug('feed-test-pkg');
  const vulnId = `TEST-${pkg}`;
  let owner: PrismaClient;
  let app: PrismaClient;
  let store: FeedStore;
  let feed: VulnFeedService;

  const osvResponse = {
    vulns: [
      {
        id: vulnId,
        aliases: ['CVE-2099-0001'],
        summary: 'test advisory',
        severity: [{ type: 'CVSS_V3', score: '9.1' }],
        affected: [
          {
            package: { name: pkg, ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }],
          },
        ],
      },
    ],
  };

  const nvdId = 'CVE-2099-0001';
  const ghsaId = `GHSA-test-${pkg}`.slice(0, 25);

  beforeAll(() => {
    owner = ownerClient();
    app = appClient();
    store = new FeedStore();
    feed = new VulnFeedService(store);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        const href = String(url);
        if (href.includes('/advisories')) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        if (href.includes('/cves/2.0')) {
          return new Response(JSON.stringify({ vulnerabilities: [] }), { status: 200 });
        }
        if (init?.method === 'POST' || href.includes('/query')) {
          return new Response(JSON.stringify(osvResponse), { status: 200 });
        }
        return new Response(JSON.stringify(osvResponse), { status: 200 });
      }),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    await owner.vulnerability.deleteMany({ where: { id: { in: [vulnId, nvdId, ghsaId] } } });
    await owner.vulnPackageSync.deleteMany({ where: { packageName: pkg } });
    await Promise.all([owner.$disconnect(), app.$disconnect(), store.$disconnect()]);
  });

  it('mirrors a package: advisory row, package index, fresh sync row', async () => {
    const mirrored = await feed.mirrorPackages([{ ecosystem: 'npm', name: pkg }]);
    expect(mirrored).toBe(1);

    const row = await owner.vulnerability.findUnique({
      where: { id: vulnId },
      include: { affects: true },
    });
    expect(row).toMatchObject({ source: 'OSV', severity: 'critical', cvssScore: 9.1 });
    expect(row!.affects).toEqual([
      expect.objectContaining({ ecosystem: 'npm', packageName: pkg }),
    ]);

    const sync = await owner.vulnPackageSync.findUnique({
      where: { ecosystem_packageName: { ecosystem: 'npm', packageName: pkg } },
    });
    expect(sync?.advisories).toBe(1);
  });

  it('skips packages whose sync row is still fresh', async () => {
    expect(await feed.mirrorPackages([{ ecosystem: 'npm', name: pkg }])).toBe(0);
  });

  it('re-mirroring is idempotent for the advisory and its index', async () => {
    await owner.vulnPackageSync.update({
      where: { ecosystem_packageName: { ecosystem: 'npm', packageName: pkg } },
      data: { syncedAt: new Date(0) },
    });
    expect(await feed.mirrorPackages([{ ecosystem: 'npm', name: pkg }])).toBe(1);
    expect(await owner.vulnerabilityAffects.count({ where: { vulnId } })).toBe(1);
  });

  it('ingests GHSA + NVD onto the same mirror tables', async () => {
    const other = uniqueSlug('feed-nvd-pkg');
    const osvId = `TEST-${other}`;
    const cve = 'CVE-2099-4242';
    const ghsa = 'GHSA-aaaa-bbbb-cccc';

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const href = String(url);
        if (href.includes('/advisories')) {
          return new Response(
            JSON.stringify([
              {
                ghsa_id: ghsa,
                cve_id: cve,
                summary: 'ghsa advisory',
                description: 'from github',
                cvss: { score: 8.1, vector_string: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' },
                vulnerabilities: [
                  {
                    package: { ecosystem: 'npm', name: other },
                    vulnerable_version_range: '< 2.0.0',
                    first_patched_version: { identifier: '2.0.0' },
                  },
                ],
              },
            ]),
            { status: 200 },
          );
        }
        if (href.includes('/cves/2.0')) {
          return new Response(
            JSON.stringify({
              vulnerabilities: [
                {
                  cve: {
                    id: cve,
                    descriptions: [{ lang: 'en', value: 'official nvd text' }],
                    metrics: {
                      cvssMetricV31: [
                        {
                          type: 'Primary',
                          cvssData: {
                            baseScore: 9.8,
                            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                            baseSeverity: 'CRITICAL',
                          },
                        },
                      ],
                    },
                  },
                },
              ],
            }),
            { status: 200 },
          );
        }
        return new Response(
          JSON.stringify({
            vulns: [
              {
                id: osvId,
                aliases: [cve],
                summary: 'osv advisory',
                severity: [{ type: 'CVSS_V3', score: '5.0' }],
                affected: [{ package: { name: other, ecosystem: 'npm' }, ranges: [] }],
              },
            ],
          }),
          { status: 200 },
        );
      }),
    );

    try {
      expect(await feed.mirrorPackages([{ ecosystem: 'npm', name: other }])).toBe(1);

      const ghsaRow = await owner.vulnerability.findUnique({
        where: { id: ghsa },
        include: { affects: true },
      });
      expect(ghsaRow).toMatchObject({ source: 'GHSA', aliases: [cve] });
      expect(ghsaRow!.affects).toEqual([
        expect.objectContaining({ ecosystem: 'npm', packageName: other }),
      ]);
      // NVD overlays official CVSS onto the alias that had no better score...
      // GHSA already had 8.1, so overlay skips; the CVE row itself is NVD.
      const nvdRow = await owner.vulnerability.findUnique({ where: { id: cve } });
      expect(nvdRow).toMatchObject({ source: 'NVD', cvssScore: 9.8, severity: 'critical' });

      const osvRow = await owner.vulnerability.findUnique({ where: { id: osvId } });
      expect(osvRow).toMatchObject({ source: 'OSV', aliases: [cve] });
    } finally {
      await owner.vulnPackageSync.deleteMany({ where: { packageName: other } });
      await owner.vulnerability.deleteMany({ where: { id: { in: [osvId, ghsa, cve] } } });
    }
  });

  it('pages recent GHSA + NVD feeds into the shared tables without a sync row', async () => {
    const cve = 'CVE-2099-7777';
    const ghsa = 'GHSA-feed-bulk-xxxx';
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const href = String(url);
        if (href.includes('/advisories')) {
          return new Response(
            JSON.stringify([
              {
                ghsa_id: ghsa,
                cve_id: cve,
                summary: 'bulk ghsa',
                vulnerabilities: [{ package: { ecosystem: 'npm', name: 'left-pad' } }],
              },
            ]),
            { status: 200 },
          );
        }
        if (href.includes('/cves/2.0')) {
          return new Response(
            JSON.stringify({
              startIndex: 0,
              resultsPerPage: 1,
              totalResults: 1,
              vulnerabilities: [
                {
                  cve: {
                    id: cve,
                    descriptions: [{ lang: 'en', value: 'bulk nvd' }],
                    metrics: {
                      cvssMetricV31: [
                        { type: 'Primary', cvssData: { baseScore: 4.3, baseSeverity: 'MEDIUM' } },
                      ],
                    },
                  },
                },
              ],
            }),
            { status: 200 },
          );
        }
        return new Response('unexpected', { status: 500 });
      }),
    );

    try {
      const summary = await feed.ingestRecentFeeds();
      expect(summary.ghsa).toBeGreaterThanOrEqual(1);
      expect(summary.nvd).toBeGreaterThanOrEqual(1);
      expect(await owner.vulnerability.findUnique({ where: { id: ghsa } })).toMatchObject({
        source: 'GHSA',
        cvssScore: 4.3,
      });
      expect(await owner.vulnerability.findUnique({ where: { id: cve } })).toMatchObject({
        source: 'NVD',
        cvssScore: 4.3,
      });
      expect(await owner.vulnPackageSync.count({ where: { packageName: 'left-pad' } })).toBe(0);
    } finally {
      await owner.vulnerability.deleteMany({ where: { id: { in: [ghsa, cve] } } });
    }
  });

  it('app role can read the mirror but not write it', async () => {
    expect(await app.vulnerability.count({ where: { id: vulnId } })).toBe(1);
    expect(await app.vulnPackageSync.count({ where: { packageName: pkg } })).toBe(1);

    await expect(
      app.vulnerabilityAffects.create({
        data: { vulnId, ecosystem: 'npm', packageName: 'sneaky' },
      }),
    ).rejects.toThrow(/permission denied/i);
    await expect(
      app.vulnPackageSync.create({
        data: { ecosystem: 'npm', packageName: 'sneaky', syncedAt: new Date() },
      }),
    ).rejects.toThrow(/permission denied/i);
  });
});

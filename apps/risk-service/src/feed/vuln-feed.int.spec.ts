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

  beforeAll(() => {
    owner = ownerClient();
    app = appClient();
    store = new FeedStore();
    feed = new VulnFeedService(store);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify(osvResponse), { status: 200 })),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    await owner.vulnerability.deleteMany({ where: { id: vulnId } });
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

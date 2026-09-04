import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { ownerClient, uniqueSlug } from '@ctem/testing';
import { VulnMatcher, type MatchableComponent } from './vuln.matcher';

/**
 * Local-first matching against a real mirrored advisory. fetch is stubbed to
 * explode, so a passing test is proof the fresh-mirror path never touches the
 * network — the entire point of the mirror.
 */
describe('VulnMatcher local mirror (integration)', () => {
  const pkg = uniqueSlug('matcher-test-pkg');
  const vulnId = `TEST-${pkg}`;
  let owner: PrismaClient;
  let prisma: PrismaService;
  let matcher: VulnMatcher;

  const component = (version: string): MatchableComponent => ({
    name: pkg,
    version,
    ecosystem: 'npm',
  });

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    matcher = new VulnMatcher(prisma);

    await owner.vulnerability.create({
      data: {
        id: vulnId,
        source: 'OSV',
        aliases: ['CVE-2099-0002'],
        summary: 'mirrored test advisory',
        severity: 'high',
        cvssScore: 7.5,
        affected: [
          {
            package: { name: pkg, ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.4.2' }] }],
          },
        ],
        affects: { create: [{ ecosystem: 'npm', packageName: pkg }] },
      },
    });
    await owner.vulnPackageSync.create({
      data: { ecosystem: 'npm', packageName: pkg, syncedAt: new Date(), advisories: 1 },
    });

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network access attempted — mirror should have answered');
      }),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    await owner.vulnPackageSync.deleteMany({ where: { packageName: pkg } });
    await owner.vulnerability.deleteMany({ where: { id: vulnId } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('answers from the mirror without touching the network', async () => {
    const { matches, mirrored } = await matcher.match(component('1.2.0'));
    expect(mirrored).toBe(true);
    expect(matches).toEqual([
      expect.objectContaining({
        id: vulnId,
        severity: 'high',
        cvssScore: 7.5,
        fixedVersion: '1.4.2',
      }),
    ]);
  });

  it('excludes versions outside the affected range', async () => {
    const { matches, mirrored } = await matcher.match(component('1.4.2'));
    expect(mirrored).toBe(true);
    expect(matches).toEqual([]);
  });

  it('keeps a stale sync row on the local mirror — no live OSV', async () => {
    await owner.vulnPackageSync.update({
      where: { ecosystem_packageName: { ecosystem: 'npm', packageName: pkg } },
      data: { syncedAt: new Date(0) },
    });
    const { matches, mirrored } = await matcher.match(component('1.2.0'));
    expect(mirrored).toBe(true);
    expect(matches).toEqual([expect.objectContaining({ id: vulnId })]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('falls back to live matching for packages the mirror has never seen', async () => {
    const { matches, mirrored } = await matcher.match({
      ...component('1.0.0'),
      name: `${pkg}-unmirrored`,
    });
    expect(mirrored).toBe(false);
    expect(matches).toEqual([]); // live path hit the stubbed-broken fetch and failed open
  });
});

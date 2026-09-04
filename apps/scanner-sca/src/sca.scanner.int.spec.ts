import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { ownerClient, uniqueSlug } from '@ctem/testing';
import { type GitRepoCheckout, type ScanContext } from '@ctem/scanner-sdk';
import type { ArtifactStore } from '@ctem/storage';
import { ScaScanner } from './sca.scanner';
import { SbomParser } from './sbom.parser';
import { VulnMatcher } from '@ctem/vuln-intel';

/**
 * Source path (no SBOM key): lockfile resolution + local-mirror matching.
 * fetch is stubbed to explode so a pass proves the run never left the building.
 */
describe('ScaScanner lockfile → local mirror (integration)', () => {
  const pkg = uniqueSlug('lockfile-pkg');
  const vulnId = `TEST-${pkg}`;
  let owner: PrismaClient;
  let prisma: PrismaService;
  let workDir: string;

  beforeAll(async () => {
    owner = ownerClient();
    prisma = new PrismaService();
    workDir = await mkdtemp(join(tmpdir(), 'ctem-sca-lock-'));

    await writeFile(
      join(workDir, 'package-lock.json'),
      JSON.stringify({
        name: 'lockfile-int',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { [pkg]: '1.2.0' } },
          [`node_modules/${pkg}`]: {
            version: '1.2.0',
            resolved: `https://registry.npmjs.org/${pkg}/-/${pkg}-1.2.0.tgz`,
            dependencies: { [`${pkg}-lib`]: '0.1.0' },
          },
          [`node_modules/${pkg}-lib`]: {
            version: '0.1.0',
            resolved: `https://registry.npmjs.org/${pkg}-lib/-/${pkg}-lib-0.1.0.tgz`,
          },
        },
      }),
    );

    await owner.vulnerability.create({
      data: {
        id: vulnId,
        source: 'OSV',
        aliases: ['CVE-2099-0003'],
        summary: 'lockfile-path mirrored advisory',
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
        throw new Error('network access attempted — lockfile path should stay on the mirror');
      }),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    await owner.vulnPackageSync.deleteMany({ where: { packageName: pkg } });
    await owner.vulnerability.deleteMany({ where: { id: vulnId } });
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('resolves the lockfile graph and matches through the local mirror', async () => {
    const checkout = { checkout: vi.fn(async () => undefined) };
    const scanner = new ScaScanner(
      new SbomParser(null as unknown as ArtifactStore),
      new VulnMatcher(prisma),
      checkout as unknown as GitRepoCheckout,
    );

    const ctx: ScanContext = {
      job: {
        jobId: randomUUID(),
        scanId: randomUUID(),
        orgId: randomUUID(),
        scannerType: 'sca',
        assetId: randomUUID(),
        target: { kind: 'repository', externalKey: 'github:acme/app' },
        credentialRef: null,
        options: {},
        attempt: 1,
        deadlineAt: new Date(Date.now() + 60_000),
        traceId: 'int-lockfile',
      },
      workDir,
      checkDeadline: () => true,
      log: () => undefined,
    };

    const outcome = await scanner.execute(ctx);

    expect(checkout.checkout).toHaveBeenCalledOnce();
    const components = (outcome.rawOutput as { components: Array<{ name: string; direct: boolean; dependencyPath: string[] }> })
      .components;
    expect(components).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: pkg, version: '1.2.0', direct: true, dependencyPath: [pkg] }),
        expect.objectContaining({
          name: `${pkg}-lib`,
          version: '0.1.0',
          direct: false,
          dependencyPath: [pkg, `${pkg}-lib`],
        }),
      ]),
    );
    expect(outcome.findings).toEqual([
      expect.objectContaining({
        externalId: vulnId,
        evidence: expect.objectContaining({
          direct: true,
          dependencyPath: [pkg],
          reachability: 'unknown',
        }),
      }),
    ]);
    // Only `pkg` has a sync row. The transitive is the first-seen live hop —
    // that is the product, not a scanner miss.
    expect(outcome.stats?.mirroredComponents).toBe(1);
    expect(outcome.vulnPackagesObserved).toEqual([
      { ecosystem: 'npm', name: `${pkg}-lib` },
    ]);
  });
});

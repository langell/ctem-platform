import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import type { ScanContext } from '@ctem/scanner-sdk';
import type { ArtifactStore } from '@ctem/storage';
import { ScaScanner } from './sca.scanner';
import { SbomParser } from './sbom.parser';
import { VulnMatcher } from './vuln.matcher';
import { CheckoutError, GitRepoCheckout } from './repo.checkout';
import { LockfileResolutionError } from './lockfiles/resolve';

const FIX = join(__dirname, 'lockfiles', '__fixtures__', 'npm');

function ctx(overrides: Partial<ScanContext['job']> = {}): ScanContext {
  return {
    job: {
      jobId: randomUUID(),
      scanId: randomUUID(),
      orgId: randomUUID(),
      scannerType: 'sca',
      assetId: randomUUID(),
      target: { kind: 'repository', htmlUrl: 'https://github.com/acme/app', defaultBranch: 'main' },
      credentialRef: null,
      options: {},
      attempt: 1,
      deadlineAt: new Date(Date.now() + 60_000),
      traceId: 'test',
      ...overrides,
    },
    workDir: FIX,
    checkDeadline: () => true,
    log: () => undefined,
  };
}

describe('ScaScanner source path', () => {
  it('resolves lockfiles when no SBOM key is given and leaves reachability unknown', async () => {
    const matcher = {
      match: vi.fn(async () => ({
        matches: [
          {
            id: 'GHSA-test',
            source: 'GHSA',
            aliases: [],
            summary: 'test advisory',
            severity: 'high',
            cvssVector: null,
            cvssScore: 7.5,
            epssScore: null,
            kev: false,
            fixedVersion: '4.17.3',
          },
        ],
        mirrored: true,
      })),
      warmCache: vi.fn(),
    };

    const checkout = { checkout: vi.fn(async () => undefined) };
    const scanner = new ScaScanner(
      new SbomParser(null as unknown as ArtifactStore),
      matcher as unknown as VulnMatcher,
      checkout as unknown as GitRepoCheckout,
    );

    const outcome = await scanner.execute(ctx());

    expect(checkout.checkout).toHaveBeenCalledOnce();
    expect(matcher.match).toHaveBeenCalled();
    const express = (outcome.rawOutput as { components: Array<{ name: string }> }).components.find(
      (c) => c.name === 'express',
    );
    expect(express).toMatchObject({ version: '4.17.1', direct: true });
    expect(outcome.findings.length).toBeGreaterThan(0);
    expect(outcome.findings.every((f) => f.evidence.reachability === 'unknown')).toBe(true);
    expect(outcome.findings[0].evidence.dependencyPath).toEqual(['express']);
    expect(outcome.stats?.mirroredComponents).toBeGreaterThan(0);
  });

  it('does not clone when an SBOM artifact key is supplied', async () => {
    const sbom = {
      fromArtifact: vi.fn(async () => [
        {
          purl: 'pkg:npm/express@4.17.1',
          name: 'express',
          version: '4.17.1',
          ecosystem: 'npm',
          direct: true,
          dependencyPath: ['express'],
          licenses: [],
        },
      ]),
    };
    const matcher = {
      match: vi.fn(async () => ({ matches: [], mirrored: true })),
      warmCache: vi.fn(),
    };
    const checkout = { checkout: vi.fn() };
    const scanner = new ScaScanner(
      sbom as unknown as SbomParser,
      matcher as unknown as VulnMatcher,
      checkout as unknown as GitRepoCheckout,
    );

    await scanner.execute(ctx({ options: { sbomArtifactKey: 'org/sbom.json' } }));
    expect(checkout.checkout).not.toHaveBeenCalled();
    expect(sbom.fromArtifact).toHaveBeenCalledWith('org/sbom.json');
  });

  it('throws on a missing or refused clone URL instead of succeeding with findings:[]', async () => {
    const matcher = { match: vi.fn(), warmCache: vi.fn() };
    const scanner = new ScaScanner(
      new SbomParser(null as unknown as ArtifactStore),
      matcher as unknown as VulnMatcher,
      new GitRepoCheckout(),
    );

    await expect(
      scanner.execute(ctx({ target: { kind: 'repository', htmlUrl: 'https://github.com/acme/app' } })),
    ).rejects.toThrow(CheckoutError);
    await expect(
      scanner.execute(ctx({ target: { cloneUrl: 'https://evil.example/acme/app.git' } })),
    ).rejects.toThrow(/only github.com and gitlab.com are allowlisted/);
    await expect(
      scanner.execute(ctx({ target: { cloneUrl: 'git@github.com:acme/app.git' } })),
    ).rejects.toThrow(/git@/);
    await expect(
      scanner.execute(
        ctx({
          target: {
            kind: 'repository',
            externalKey: 'github:acme/app',
            cloneUrl: 'https://github.com/evil/other.git',
          },
        }),
      ),
    ).rejects.toThrow(/does not match asset identity/);
    expect(matcher.match).not.toHaveBeenCalled();
  });

  it('throws when every lockfile parser fails rather than returning an empty success', async () => {
    const matcher = { match: vi.fn(), warmCache: vi.fn() };
    const checkout = { checkout: vi.fn(async () => undefined) };
    const scanner = new ScaScanner(
      new SbomParser(null as unknown as ArtifactStore),
      matcher as unknown as VulnMatcher,
      checkout as unknown as GitRepoCheckout,
    );

    await expect(
      scanner.execute({
        ...ctx(),
        workDir: join(__dirname, 'lockfiles', '__fixtures__', 'corrupt'),
      }),
    ).rejects.toThrow(LockfileResolutionError);
    expect(matcher.match).not.toHaveBeenCalled();
  });
});

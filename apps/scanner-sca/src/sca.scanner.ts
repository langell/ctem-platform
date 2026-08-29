import { Injectable } from '@nestjs/common';
import { BaseScanner, type ScanContext, type ScanOutcome } from '@ctem/scanner-sdk';
import type { RawFinding, ScannerType } from '@ctem/contracts';
import { SbomParser, type ResolvedComponent } from './sbom.parser';
import { VulnMatcher } from './vuln.matcher';
import { resolveLockfiles } from './lockfiles';
import { GitRepoCheckout } from './repo.checkout';

/**
 * Software Composition Analysis — dependencies and SBOMs.
 *
 * Two input paths:
 *   1. CI uploaded a CycloneDX/SPDX document; we parse it and match. Fast, no
 *      repo access needed, and the customer's build already resolved versions.
 *   2. We were given a repo; we resolve the manifest ourselves.
 *
 * The differentiator versus a plain "CVE grep" is reachability: knowing a
 * vulnerable function is actually called changes a wall of criticals into a
 * short list. That lives behind `analyzeReachability` and is the highest-value
 * piece of unbuilt work in this scanner.
 */
@Injectable()
export class ScaScanner extends BaseScanner {
  readonly type: ScannerType = 'sca';
  readonly name = 'ctem-sca';
  readonly version = '0.1.0';

  constructor(
    private readonly sbom: SbomParser,
    private readonly matcher: VulnMatcher,
    private readonly checkout: GitRepoCheckout = new GitRepoCheckout(),
  ) {
    super();
  }

  async onReady(): Promise<void> {
    await this.matcher.warmCache();
  }

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    const sbomKey = ctx.job.options.sbomArtifactKey as string | undefined;

    const components: ResolvedComponent[] = sbomKey
      ? await this.sbom.fromArtifact(sbomKey)
      : await this.resolveFromSource(ctx);

    ctx.log(`resolved ${components.length} components`);

    const findings: RawFinding[] = [];
    const observed = new Map<string, { ecosystem: string; name: string }>();
    let mirroredCount = 0;
    for (const component of components) {
      if (!ctx.checkDeadline()) throw new Error('Job deadline exceeded');
      const { matches, mirrored } = await this.matcher.match(component);
      if (mirrored) {
        mirroredCount += 1;
      } else if (component.ecosystem !== 'unknown') {
        observed.set(`${component.ecosystem}:${component.name}`, {
          ecosystem: component.ecosystem,
          name: component.name,
        });
      }
      for (const vuln of matches) {
        findings.push({
          externalId: vuln.id,
          scannerType: 'sca',
          scannerName: this.name,
          title: `${vuln.id} in ${component.name}@${component.version}`,
          description: vuln.summary,
          severity: vuln.severity,
          identifiers: [{ system: vuln.source, value: vuln.id }, ...vuln.aliases.map((a) => ({ system: 'alias', value: a }))],
          cvssVector: vuln.cvssVector,
          cvssScore: vuln.cvssScore,
          epssScore: vuln.epssScore,
          kev: vuln.kev,
          location: {
            packageName: component.name,
            packageVersion: component.version,
            packageEcosystem: component.ecosystem,
            purl: component.purl,
            path: component.manifestPath,
          },
          fix: {
            available: Boolean(vuln.fixedVersion),
            fixedVersion: vuln.fixedVersion,
            guidance: vuln.fixedVersion
              ? `Upgrade ${component.name} to ${vuln.fixedVersion}`
              : 'No fixed version published yet',
          },
          evidence: {
            direct: component.direct,
            dependencyPath: component.dependencyPath,
            // TODO: reachability verdict from static call-graph analysis.
            reachability: 'unknown',
          },
          raw: {},
        });
      }
    }

    return {
      findings,
      rawOutput: { components, scannedAt: new Date().toISOString() },
      stats: {
        components: components.length,
        direct: components.filter((c) => c.direct).length,
        findings: findings.length,
        mirroredComponents: mirroredCount,
      },
      vulnPackagesObserved: [...observed.values()],
    };
  }

  /**
   * Repo path: clone at the pinned ref, detect ecosystems, resolve lockfiles.
   * Lockfile-first — a range in package.json is a guess, a lockfile is the truth.
   *
   * Reachability (call-graph analysis) is deliberately not done here. Findings
   * keep `evidence.reachability = 'unknown'` until that slice ships.
   */
  private async resolveFromSource(ctx: ScanContext): Promise<ResolvedComponent[]> {
    await this.checkout.checkout(ctx);
    return resolveLockfiles(ctx.workDir);
  }
}

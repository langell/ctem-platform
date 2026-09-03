import { Injectable } from '@nestjs/common';
import { BaseScanner, GitRepoCheckout, type ScanContext, type ScanOutcome } from '@ctem/scanner-sdk';
import type { RawFinding, ScannerType } from '@ctem/contracts';
import { SbomParser, type ResolvedComponent } from './sbom.parser';
import { VulnMatcher } from './vuln.matcher';
import { resolveLockfiles } from './lockfiles';
import {
  isReachabilityGraph,
  ReachabilityAnalysisError,
  ReachabilityAnalyzer,
  verdictForComponent,
  type ReachabilityGraph,
  type ReachabilityVerdict,
} from './reachability';

/**
 * Software Composition Analysis — dependencies and SBOMs.
 *
 * Two input paths:
 *   1. CI uploaded a CycloneDX/SPDX document; we parse it and match. Fast, no
 *      repo access needed, and the customer's build already resolved versions.
 *   2. We were given a repo; we resolve the manifest ourselves, then fill
 *      evidence.reachability from an import/call graph of that clone.
 *
 * Lockfile presence is not reachability. `reachable` / `not_reachable` only
 * land when the graph says so. A package the graph cannot prove stays
 * `unknown`. If analysis crashes, times out, or never produces a graph, the
 * job fails — never an empty or all-unknown success from a failed analysis.
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
    private readonly reachability: ReachabilityAnalyzer = new ReachabilityAnalyzer(),
  ) {
    super();
  }

  async onReady(): Promise<void> {
    await this.matcher.warmCache();
  }

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    const sbomKey = ctx.job.options.sbomArtifactKey as string | undefined;

    const { components, graph } = sbomKey
      ? { components: await this.sbom.fromArtifact(sbomKey), graph: undefined }
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
      const reachability: ReachabilityVerdict = graph
        ? verdictForComponent(component, graph)
        : 'unknown';
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
            reachability,
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
   * Repo path: clone at the pinned ref, resolve lockfiles, then build the
   * import/call graph on that workDir. Graph analysis is required: a crash or
   * missing graph fails the job so findings-service cannot auto-resolve prior
   * SCA hits from an empty or all-unknown success.
   */
  private async resolveFromSource(
    ctx: ScanContext,
  ): Promise<{ components: ResolvedComponent[]; graph: ReachabilityGraph }> {
    await this.checkout.checkout(ctx);
    const components = await resolveLockfiles(ctx.workDir);
    let graph: unknown;
    try {
      graph = await this.reachability.analyze(ctx.workDir, ctx.checkDeadline);
    } catch (err) {
      if (err instanceof ReachabilityAnalysisError) throw err;
      throw new ReachabilityAnalysisError(
        `Reachability analysis failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (!isReachabilityGraph(graph)) {
      throw new ReachabilityAnalysisError(
        'Reachability analyzer did not produce a graph — refusing an all-unknown success',
      );
    }
    return { components, graph };
  }
}

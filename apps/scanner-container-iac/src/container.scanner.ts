import { Injectable } from '@nestjs/common';
import { BaseScanner, type ScanContext, type ScanOutcome } from '@ctem/scanner-sdk';
import type { RawFinding, ScanJob, ScannerType } from '@ctem/contracts';
import { VulnMatcher } from '@ctem/vuln-intel';
import { optionalGithubToken, requireGithubToken, ContainerCredentialError } from './container.credential';
import { ContainerEgressError } from './container.egress';
import {
  isPrivateContainerImage,
  parseGhcrImageRef,
  ContainerIdentityError,
} from './container.identity';
import { inventoryImage, ContainerInventoryError, type ImagePackage } from './inventory/packages';
import { ContainerPullError, GhcrRegistry } from './oci/registry';
import { LayerUnpackError } from './oci/tar';

export class ContainerScanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContainerScanError';
  }
}

const TENANT_ANALYZER_KEYS = [
  'script',
  'rulesYaml',
  'customRules',
  'docker',
  'podman',
  'skopeo',
  'crane',
  'trivy',
  'grype',
  'syft',
] as const;

/**
 * Container image scanning over GHCR-discovered `container_image` assets.
 *
 * Pull allowlisted `ghcr.io` digests in-process (manifest + layer blobs),
 * inventory OS/app packages per layer, and match the shared vuln mirror.
 * `kubernetes_workload` stays unimplemented (throw, never empty success).
 * `repository` / `iac_stack` belong to IacScanner.
 */
@Injectable()
export class ContainerScanner extends BaseScanner {
  readonly type: ScannerType = 'container';
  readonly name = 'ctem-container';
  readonly version = '0.1.0';

  constructor(
    private readonly matcher: VulnMatcher,
    private readonly registry: GhcrRegistry,
  ) {
    super();
  }

  supports(job: ScanJob): boolean {
    return job.target.kind === 'container_image' || job.target.kind === 'kubernetes_workload';
  }

  async onReady(): Promise<void> {
    await this.matcher.warmCache();
  }

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    const kind = String(ctx.job.target.kind ?? '');
    if (kind === 'kubernetes_workload') {
      throw new ContainerScanError(
        "Container scanning for 'kubernetes_workload' is not implemented — refusing empty success (no cluster inventory)",
      );
    }
    if (kind !== 'container_image') {
      throw new ContainerScanError(
        `Container scanning for '${kind}' is not implemented — refusing empty success (no layer pull, no OCI inventory)`,
      );
    }

    const ignored = tenantAnalyzerOptions(ctx.job.options);
    if (ignored.length) {
      ctx.log('ignoring tenant-supplied analyzer options', { keys: ignored });
    }

    if (!ctx.checkDeadline()) {
      throw new ContainerScanError('Job deadline exceeded');
    }

    try {
      return await this.scanImage(ctx, ignored);
    } catch (err) {
      if (
        err instanceof ContainerScanError ||
        err instanceof ContainerIdentityError ||
        err instanceof ContainerCredentialError ||
        err instanceof ContainerEgressError ||
        err instanceof ContainerPullError ||
        err instanceof ContainerInventoryError ||
        err instanceof LayerUnpackError
      ) {
        throw err;
      }
      throw new ContainerScanError(
        `Container scan failed: ${err instanceof Error ? err.message : String(err)} — refusing incomplete success`,
      );
    }
  }

  private async scanImage(ctx: ScanContext, ignored: string[]): Promise<ScanOutcome> {
    const ref = parseGhcrImageRef(ctx.job.target, ctx.job.options);
    const token = isPrivateContainerImage(ctx.job.target)
      ? requireGithubToken(ctx.job.credentialRef)
      : optionalGithubToken(ctx.job.credentialRef);

    ctx.log(`pulling ghcr.io/${ref.owner}/${ref.name}@${ref.digest}`);
    const pulled = await this.registry.pull(ref, token, ctx.checkDeadline);

    if (!ctx.checkDeadline()) {
      throw new ContainerScanError('Job deadline exceeded after pull — refusing incomplete inventory');
    }

    const packages = inventoryImage(pulled.layers);
    ctx.log(`inventoried ${packages.length} packages across ${pulled.layers.length} layers`);

    const findings: RawFinding[] = [];
    const observed = new Map<string, { ecosystem: string; name: string }>();
    let mirroredCount = 0;

    for (const pkg of packages) {
      if (!ctx.checkDeadline()) {
        throw new ContainerScanError('Job deadline exceeded during vuln match — refusing incomplete success');
      }
      const { matches, mirrored } = await this.matcher.match({
        name: pkg.name,
        version: pkg.version,
        ecosystem: pkg.ecosystem,
      });
      if (mirrored) {
        mirroredCount += 1;
      } else if (pkg.ecosystem !== 'unknown') {
        observed.set(`${pkg.ecosystem}:${pkg.name}`, { ecosystem: pkg.ecosystem, name: pkg.name });
      }
      for (const vuln of matches) {
        findings.push(toFinding(this.name, pkg, vuln));
      }
    }

    return {
      findings,
      rawOutput: {
        image: `ghcr.io/${ref.owner}/${ref.name}@${ref.digest}`,
        layers: pulled.layers.map((layer) => layer.digest),
        packages: packages.map((pkg) => ({
          name: pkg.name,
          version: pkg.version,
          ecosystem: pkg.ecosystem,
          purl: pkg.purl,
          layerDigest: pkg.layerDigest,
          path: pkg.path,
        })),
        complete: true,
        truncated: false,
        ignoredTenantOptions: ignored,
        scannedAt: new Date().toISOString(),
      },
      stats: {
        findings: findings.length,
        packages: packages.length,
        layers: pulled.layers.length,
        mirroredComponents: mirroredCount,
      },
      vulnPackagesObserved: [...observed.values()],
    };
  }
}

function toFinding(
  scannerName: string,
  pkg: ImagePackage,
  vuln: {
    id: string;
    source: string;
    aliases: string[];
    summary: string;
    severity: RawFinding['severity'];
    cvssVector: string | null;
    cvssScore: number | null;
    epssScore: number | null;
    kev: boolean;
    fixedVersion?: string;
  },
): RawFinding {
  return {
    externalId: `${vuln.id}:${pkg.purl}:${pkg.layerDigest}`,
    scannerType: 'container',
    scannerName,
    title: `${vuln.id} in ${pkg.name}@${pkg.version}`,
    description: vuln.summary,
    severity: vuln.severity,
    identifiers: [
      { system: vuln.source, value: vuln.id },
      ...vuln.aliases.map((a) => ({ system: 'alias', value: a })),
    ],
    cvssVector: vuln.cvssVector,
    cvssScore: vuln.cvssScore,
    epssScore: vuln.epssScore,
    kev: vuln.kev,
    location: {
      packageName: pkg.name,
      packageVersion: pkg.version,
      packageEcosystem: pkg.ecosystem,
      purl: pkg.purl,
      path: pkg.path,
      imageLayer: pkg.layerDigest,
    },
    fix: {
      available: Boolean(vuln.fixedVersion),
      fixedVersion: vuln.fixedVersion,
      guidance: vuln.fixedVersion
        ? `Upgrade ${pkg.name} to ${vuln.fixedVersion}`
        : 'No fixed version published yet',
    },
    evidence: {
      introducedByLayer: pkg.layerDigest,
      layerDigest: pkg.layerDigest,
      origin: pkg.origin,
      reachability: 'unknown',
    },
    raw: {},
  };
}

export function tenantAnalyzerOptions(options: Record<string, unknown>): string[] {
  return TENANT_ANALYZER_KEYS.filter((key) => {
    const value = options[key];
    return value !== undefined && value !== null && value !== '';
  });
}

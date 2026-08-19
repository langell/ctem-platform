import { Injectable } from '@nestjs/common';
import { BaseScanner, type ScanContext, type ScanOutcome } from '@ctem/scanner-sdk';
import type { RawFinding, ScanJob, ScannerType } from '@ctem/contracts';
import { rootLogger } from '@ctem/observability';
import { IacScanner } from './iac.scanner';

/**
 * Container image scanning: pull the manifest, walk the layers, inventory OS
 * packages and application dependencies, then match against advisories.
 *
 * The detail that matters for prioritization is *which layer* introduced a
 * vulnerable package. A CVE in the base image is one upgrade for a hundred
 * services; the same CVE added by an app layer is a hundred separate fixes.
 */
@Injectable()
export class ContainerScanner extends BaseScanner {
  readonly type: ScannerType = 'container';
  readonly name = 'ctem-container';
  readonly version = '0.1.0';
  private readonly log = rootLogger.child({ scanner: 'container' });

  constructor(private readonly iac: IacScanner) {
    super();
  }

  supports(job: ScanJob): boolean {
    return ['container_image', 'kubernetes_workload', 'repository', 'iac_stack'].includes(
      String(job.target.kind),
    );
  }

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    // IaC targets are handled by the sibling scanner but share this worker.
    if (['repository', 'iac_stack'].includes(String(ctx.job.target.kind))) {
      return this.iac.execute(ctx);
    }

    const imageRef = String(ctx.job.target.externalKey ?? '');
    ctx.log(`scanning image ${imageRef}`);

    // TODO: registry client (OCI distribution API) -> layer blobs -> package
    // inventory per layer. Cache by layer digest: layers are shared across
    // hundreds of images, so scanning a digest twice is pure waste.
    this.log.warn({ imageRef }, 'container layer inventory not implemented');

    const findings: RawFinding[] = [];
    return { findings, rawOutput: { imageRef, layers: [] }, stats: { layers: 0 } };
  }
}

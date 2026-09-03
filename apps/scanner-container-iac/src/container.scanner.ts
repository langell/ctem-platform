import { Injectable } from '@nestjs/common';
import { BaseScanner, type ScanContext, type ScanOutcome } from '@ctem/scanner-sdk';
import type { ScanJob, ScannerType } from '@ctem/contracts';

export class ContainerScanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContainerScanError';
  }
}

/**
 * Container image scanning is out of scope for this lock. The worker must not
 * report empty success for `container_image` / `kubernetes_workload`, and must
 * not claim `repository` / `iac_stack` (those belong to IacScanner).
 */
@Injectable()
export class ContainerScanner extends BaseScanner {
  readonly type: ScannerType = 'container';
  readonly name = 'ctem-container';
  readonly version = '0.1.0';

  supports(job: ScanJob): boolean {
    return job.target.kind === 'container_image' || job.target.kind === 'kubernetes_workload';
  }

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    const kind = String(ctx.job.target.kind ?? '');
    throw new ContainerScanError(
      `Container scanning for '${kind}' is not implemented — refusing empty success (no layer pull, no OCI inventory)`,
    );
  }
}

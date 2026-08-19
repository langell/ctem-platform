import { Injectable } from '@nestjs/common';
import { BaseScanner, type ScanContext, type ScanOutcome } from '@ctem/scanner-sdk';
import type { RawFinding, ScannerType } from '@ctem/contracts';
import { MisconfigRules } from './misconfig.rules';

/**
 * Infrastructure-as-code misconfiguration scanning. Catching a public bucket in
 * the Terraform plan is worth more than catching it in production, and it is the
 * same finding — so IaC findings link to the cloud asset they will become.
 */
@Injectable()
export class IacScanner extends BaseScanner {
  readonly type: ScannerType = 'iac';
  readonly name = 'ctem-iac';
  readonly version = '0.1.0';

  constructor(private readonly rules: MisconfigRules) {
    super();
  }

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    // TODO: clone into ctx.workDir, detect file types (*.tf, k8s manifests,
    // Chart.yaml, Dockerfile), parse to HCL/YAML AST, evaluate rules.
    ctx.log('iac scan', { rules: this.rules.rules.length });

    const findings: RawFinding[] = [];
    return { findings, rawOutput: { evaluated: 0 }, stats: { files: 0 } };
  }
}

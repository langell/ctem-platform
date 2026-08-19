import { Injectable } from '@nestjs/common';
import type { Severity } from '@ctem/contracts';

export interface MisconfigRule {
  id: string;
  title: string;
  severity: Severity;
  /** terraform | kubernetes | cloudformation | dockerfile | helm */
  targets: string[];
  remediation: string;
}

/**
 * Starter rule pack for infrastructure misconfiguration. These are the findings
 * that show up in every cloud breach post-mortem, which is why they lead.
 */
@Injectable()
export class MisconfigRules {
  readonly rules: MisconfigRule[] = [
    {
      id: 'ctem.iac.s3-public',
      title: 'Object storage bucket is publicly readable',
      severity: 'critical',
      targets: ['terraform', 'cloudformation'],
      remediation: 'Block public ACLs and enforce bucket-level public access blocking.',
    },
    {
      id: 'ctem.iac.sg-open-ssh',
      title: 'Security group exposes SSH to 0.0.0.0/0',
      severity: 'high',
      targets: ['terraform', 'cloudformation'],
      remediation: 'Restrict ingress to a bastion or your VPN CIDR.',
    },
    {
      id: 'ctem.k8s.privileged-container',
      title: 'Container runs privileged',
      severity: 'high',
      targets: ['kubernetes', 'helm'],
      remediation: 'Drop privileged: true and grant only the capabilities required.',
    },
    {
      id: 'ctem.k8s.no-resource-limits',
      title: 'Workload has no resource limits',
      severity: 'low',
      targets: ['kubernetes', 'helm'],
      remediation: 'Set CPU and memory limits so one workload cannot starve a node.',
    },
    {
      id: 'ctem.docker.root-user',
      title: 'Image runs as root',
      severity: 'medium',
      targets: ['dockerfile'],
      remediation: 'Add a non-root USER before the entrypoint.',
    },
    {
      id: 'ctem.iac.unencrypted-storage',
      title: 'Storage volume is unencrypted at rest',
      severity: 'medium',
      targets: ['terraform', 'cloudformation'],
      remediation: 'Enable encryption with a customer-managed key.',
    },
  ];

  forTarget(target: string): MisconfigRule[] {
    return this.rules.filter((r) => r.targets.includes(target));
  }
}

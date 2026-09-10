import type { Severity } from '@ctem/contracts';

export interface PostureRule {
  id: string;
  title: string;
  severity: Severity;
  remediation: string;
}

/**
 * Built-in live-cloud posture pack. Public object storage and internet-open
 * network filters (and cloud equivalents). Tenant scripts, YAML packs, and
 * aws/gcloud/az CLI invocations are never loaded or executed.
 */
export const POSTURE_RULES = {
  publicBucket: {
    id: 'ctem.cspm.public-bucket',
    title: 'Object storage is publicly readable',
    severity: 'critical',
    remediation: 'Block public ACLs/IAM and enforce account-level public access blocking.',
  },
  openSg: {
    id: 'ctem.cspm.open-sg',
    title: 'Network filter exposes ingress to the internet',
    severity: 'high',
    remediation: 'Restrict ingress to a bastion or your VPN CIDR. Do not allow 0.0.0.0/0.',
  },
} as const satisfies Record<string, PostureRule>;

export type PostureRuleId = (typeof POSTURE_RULES)[keyof typeof POSTURE_RULES]['id'];

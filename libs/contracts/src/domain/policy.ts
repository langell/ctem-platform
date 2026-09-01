import { z } from 'zod';
import { AuditMeta, OrgId, Severity } from '../common';

/**
 * Policy answers three questions: what do we block, how fast must it be fixed,
 * and who is allowed to accept the risk instead.
 */
export const PolicyAction = z.enum(['notify', 'ticket', 'fail_build', 'block_deploy', 'ignore']);

export const PolicyCondition = z.object({
  severityAtLeast: Severity.optional(),
  minRiskScore: z.number().min(0).max(100).optional(),
  kevOnly: z.boolean().optional(),
  minEpss: z.number().min(0).max(1).optional(),
  requireFixAvailable: z.boolean().optional(),
  scannerTypes: z.array(z.string()).optional(),
  assetKinds: z.array(z.string()).optional(),
  assetTags: z.record(z.string()).optional(),
  exposure: z.array(z.string()).optional(),
  criticality: z.array(z.string()).optional(),
});
export type PolicyCondition = z.infer<typeof PolicyCondition>;

export const Policy = z
  .object({
    id: z.string().uuid(),
    orgId: OrgId,
    name: z.string().min(1),
    description: z.string().default(''),
    enabled: z.boolean().default(true),
    /** Lower runs first; the first matching terminal action wins. */
    priority: z.number().int().default(100),
    condition: PolicyCondition,
    actions: z.array(PolicyAction).min(1),
    /** Hours to remediate once a finding matches; drives slaDueAt on findings. */
    slaHours: z.number().int().positive().nullable().default(null),
  })
  .merge(AuditMeta);
export type Policy = z.infer<typeof Policy>;

/**
 * Tenant-authored writes in this slice: notify only. Ticket / fail-build /
 * block-deploy stay on the stored Policy shape (seed + engine) but cannot be
 * created or updated through the editor API.
 */
export const NotifyOnlyActions = z.array(z.literal('notify')).min(1);
export type NotifyOnlyActions = z.infer<typeof NotifyOnlyActions>;

/** Field names a tenant might use to inject a webhook URL. Refused on write. */
export const TENANT_WEBHOOK_KEYS = [
  'webhookUrl',
  'webhook',
  'url',
  'target',
  'hookUrl',
  'slackWebhook',
  'webhook_url',
] as const;

export function findTenantWebhookKeys(input: unknown, path = ''): string[] {
  if (!input || typeof input !== 'object') return [];
  if (Array.isArray(input)) {
    return input.flatMap((value, index) => findTenantWebhookKeys(value, `${path}[${index}]`));
  }
  const record = input as Record<string, unknown>;
  const hits: string[] = [];
  for (const [key, value] of Object.entries(record)) {
    const here = path ? `${path}.${key}` : key;
    if ((TENANT_WEBHOOK_KEYS as readonly string[]).includes(key)) hits.push(here);
    hits.push(...findTenantWebhookKeys(value, here));
  }
  return hits;
}

export const CreatePolicyRequest = Policy.omit({
  id: true,
  orgId: true,
  createdAt: true,
  updatedAt: true,
})
  .extend({
    actions: NotifyOnlyActions,
  })
  .strict();
export type CreatePolicyRequest = z.infer<typeof CreatePolicyRequest>;

export const UpdatePolicyRequest = CreatePolicyRequest.partial().strict();
export type UpdatePolicyRequest = z.infer<typeof UpdatePolicyRequest>;

export const ExceptionScope = z.enum(['finding', 'asset', 'vulnerability', 'global']);

export const RiskException = z
  .object({
    id: z.string().uuid(),
    orgId: OrgId,
    scope: ExceptionScope,
    /** finding id, asset id, or vulnerability identifier depending on scope. */
    targetRef: z.string(),
    reason: z.string().min(1),
    requestedBy: z.string().uuid(),
    approvedBy: z.string().uuid().nullable().default(null),
    approvedAt: z.coerce.date().nullable().default(null),
    expiresAt: z.coerce.date(),
    revokedAt: z.coerce.date().nullable().default(null),
  })
  .merge(AuditMeta);
export type RiskException = z.infer<typeof RiskException>;

/**
 * Risk scoring inputs, kept explicit so scores are explainable in the UI.
 * Weights are org-tunable — "why is this a 91?" must always have an answer.
 */
export const RiskWeights = z.object({
  severity: z.number().default(0.3),
  exploitability: z.number().default(0.25), // epss + kev
  exposure: z.number().default(0.25), // internet facing, reachable
  businessCriticality: z.number().default(0.2),
});
export type RiskWeights = z.infer<typeof RiskWeights>;

export const RiskExplanation = z.object({
  findingId: z.string().uuid(),
  score: z.number().min(0).max(100),
  factors: z.array(
    z.object({
      name: z.string(),
      weight: z.number(),
      rawValue: z.number(),
      contribution: z.number(),
      note: z.string().optional(),
    }),
  ),
  matchedPolicies: z.array(z.string()),
});
export type RiskExplanation = z.infer<typeof RiskExplanation>;

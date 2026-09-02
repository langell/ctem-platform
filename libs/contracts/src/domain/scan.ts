import { z } from 'zod';
import { AuditMeta, OrgId } from '../common';

/** One scanner family per CTEM discovery surface. Adding a scanner = adding a value here. */
export const ScannerType = z.enum([
  'sca', // dependencies + SBOM
  'sast', // source code
  'container', // image layers / OS packages
  'iac', // terraform, k8s manifests, cloudformation
  'secrets',
  'asm', // external attack surface
  'cloud_posture',
]);
export type ScannerType = z.infer<typeof ScannerType>;

export const ScanTrigger = z.enum(['scheduled', 'manual', 'webhook', 'ci', 'asset_created', 'feed_update']);
export const ScanStatus = z.enum(['queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled']);
export type ScanStatus = z.infer<typeof ScanStatus>;

/** CI reads this on GET. It is not a writeable column and not a GitHub Check. */
export const ScanConclusion = z.enum(['pending', 'passed', 'failed']);
export type ScanConclusion = z.infer<typeof ScanConclusion>;

/** Field names a client might use to force a failed CI gate. Refused on write. */
export const CLIENT_CONCLUSION_KEYS = [
  'conclusion',
  'scanConclusion',
  'scan_conclusion',
  'checkConclusion',
  'check_conclusion',
  'githubCheck',
  'github_check',
] as const;

export function findClientConclusionKeys(input: unknown): string[] {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return [];
  const record = input as Record<string, unknown>;
  const hits: string[] = [];
  for (const key of Object.keys(record)) {
    if ((CLIENT_CONCLUSION_KEYS as readonly string[]).includes(key)) hits.push(key);
  }
  const options = record.options;
  if (options && typeof options === 'object' && !Array.isArray(options)) {
    for (const key of Object.keys(options as Record<string, unknown>)) {
      if ((CLIENT_CONCLUSION_KEYS as readonly string[]).includes(key)) hits.push(`options.${key}`);
    }
  }
  return hits;
}

function refuseClientConclusion(
  value: unknown,
  ctx: z.RefinementCtx,
): void {
  const hits = findClientConclusionKeys(value);
  if (hits.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message:
        `scan conclusion is not client-writable (${hits.join(', ')}) — ` +
        'only a matching fail_build policy can fail the build',
    });
  }
}

/** Everything a worker needs to do its job, with no callback into the control plane. */
export const ScanJob = z.object({
  jobId: z.string().uuid(),
  scanId: z.string().uuid(),
  orgId: OrgId,
  scannerType: ScannerType,
  assetId: z.string().uuid(),
  /** Scanner-specific target descriptor: repo URL + ref, image ref, domain, cloud account. */
  target: z.record(z.unknown()),
  /** Short-lived credential handle resolved from the secret store, never a raw secret. */
  credentialRef: z.string().nullable().default(null),
  options: z.record(z.unknown()).default({}),
  attempt: z.number().int().min(1).default(1),
  deadlineAt: z.coerce.date(),
  traceId: z.string(),
});
export type ScanJob = z.infer<typeof ScanJob>;

export const ScanJobResult = z.object({
  jobId: z.string().uuid(),
  scanId: z.string().uuid(),
  orgId: OrgId,
  scannerType: ScannerType,
  assetId: z.string().uuid(),
  status: ScanStatus,
  startedAt: z.coerce.date(),
  finishedAt: z.coerce.date(),
  /** Object-store key for the raw scanner output; findings reference it for evidence. */
  artifactKey: z.string().nullable().default(null),
  findingCount: z.number().int().nonnegative().default(0),
  error: z.string().nullable().default(null),
  stats: z.record(z.number()).default({}),
});
export type ScanJobResult = z.infer<typeof ScanJobResult>;

export const Scan = z
  .object({
    id: z.string().uuid(),
    orgId: OrgId,
    scannerType: ScannerType,
    trigger: ScanTrigger,
    status: ScanStatus,
    requestedBy: z.string().uuid().nullable().default(null),
    assetSelector: z.record(z.unknown()).default({}),
    jobsTotal: z.number().int().nonnegative().default(0),
    jobsCompleted: z.number().int().nonnegative().default(0),
    startedAt: z.coerce.date().nullable().default(null),
    finishedAt: z.coerce.date().nullable().default(null),
    /** Computed on GET from matching fail_build rules. Never accepted on write. */
    conclusion: ScanConclusion.optional(),
  })
  .merge(AuditMeta);
export type Scan = z.infer<typeof Scan>;

export const CreateScanRequest = z
  .object({
    scannerType: ScannerType,
    /** Empty selector means "everything in scope for this scanner". */
    assetSelector: z
      .object({
        assetIds: z.array(z.string().uuid()).optional(),
        kinds: z.array(z.string()).optional(),
        tags: z.record(z.string()).optional(),
      })
      .default({}),
    options: z.record(z.unknown()).default({}),
  })
  .strict()
  .superRefine(refuseClientConclusion);
export type CreateScanRequest = z.infer<typeof CreateScanRequest>;

/** SBOM ingest is a first-class path: CI uploads a CycloneDX doc instead of us cloning the repo. */
export const SbomFormat = z.enum(['cyclonedx-json', 'spdx-json', 'syft-json']);
export const IngestSbomRequest = z
  .object({
    assetExternalKey: z.string(),
    format: SbomFormat,
    /** Object-store key of an already-uploaded document. */
    artifactKey: z.string().optional(),
    /** Or the document itself, inline — the ingest endpoint stores it. */
    document: z.record(z.unknown()).optional(),
    ref: z.string().optional(),
    commitSha: z.string().optional(),
  })
  .strict()
  .refine((r) => Boolean(r.artifactKey) !== Boolean(r.document), {
    message: 'Provide exactly one of artifactKey or document',
  })
  .superRefine(refuseClientConclusion);
export type IngestSbomRequest = z.infer<typeof IngestSbomRequest>;

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

/**
 * CI-facing GET. It is not a writeable column. GitHub Checks and GitLab
 * Commit Statuses (optional, additive) map the same concludeScan result; they
 * do not replace this field.
 */
export const ScanConclusion = z.enum(['pending', 'passed', 'failed']);
export type ScanConclusion = z.infer<typeof ScanConclusion>;

/**
 * Deploy tooling polls this on GET. Independent of `conclusion`: only a matching
 * `block_deploy` policy produces `blocked`. Callers cannot POST or PATCH it.
 * GitHub Checks stay mapped from `concludeScan` / `fail_build` only. Optional
 * GitHub Deployment statuses and GitLab Deployment updates map this field from
 * `concludeDeploy` when context is present — they do not replace GET.
 */
export const ScanDeployConclusion = z.enum(['pending', 'allowed', 'blocked']);
export type ScanDeployConclusion = z.infer<typeof ScanDeployConclusion>;

/** Field names a client might use to force a CI or deploy gate. Refused on write. */
export const CLIENT_CONCLUSION_KEYS = [
  'conclusion',
  'scanConclusion',
  'scan_conclusion',
  'checkConclusion',
  'check_conclusion',
  'githubCheck',
  'github_check',
  'deployConclusion',
  'deploy_conclusion',
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
        'only a matching fail_build policy can fail the build; ' +
        'only a matching block_deploy policy can block deploy',
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
    /** Computed on GET from matching block_deploy rules. Never accepted on write. */
    deployConclusion: ScanDeployConclusion.optional(),
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
    /**
     * Scanner options plus optional GitHub Checks / Deployments context
     * (allowlisted keys under `options.github` or top-level): `repository`
     * (`owner/name` or `owner`+`repo`), `sha` (40-char commit, Checks),
     * `deploymentId` (positive integer GitHub deployment id, Deployments),
     * optional `checkName` / `detailsUrl` / `environment` / `description` /
     * `logUrl`. `detailsUrl` and `logUrl` must be a CTEM URL.
     *
     * Optional GitLab CI Commit Status context (allowlisted keys under
     * `options.gitlab` or top-level): `projectId` (preferred GitLab
     * `path/with/namespace`, or a positive integer project id), `sha`
     * (40-char commit), optional `name` / `description` / `targetUrl` /
     * `ref`. `targetUrl` must be a CTEM URL. `ref` is a git ref, not a host.
     * Optional GitLab Deployments context (same `options.gitlab` / top-level):
     * reuse `projectId`; add `deploymentId` (positive integer GitLab
     * deployment id). Optional `environment` is an attribute only, not a host.
     * Missing `sha` is OK for Deployments (sha remains Commit-Status-only).
     * Tenant `baseUrl` / `apiUrl` / host keys on the scan are not the GitLab
     * API origin (gitlab.com, or the scan asset's GitLab connector `baseUrl`).
     *
     * Client conclusion keys stay refused — they are not Checks, Deployments,
     * or GitLab status context.
     */
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

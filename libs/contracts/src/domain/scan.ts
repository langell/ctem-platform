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
  })
  .merge(AuditMeta);
export type Scan = z.infer<typeof Scan>;

export const CreateScanRequest = z.object({
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
});
export type CreateScanRequest = z.infer<typeof CreateScanRequest>;

/** SBOM ingest is a first-class path: CI uploads a CycloneDX doc instead of us cloning the repo. */
export const SbomFormat = z.enum(['cyclonedx-json', 'spdx-json', 'syft-json']);
export const IngestSbomRequest = z.object({
  assetExternalKey: z.string(),
  format: SbomFormat,
  /** Object-store key of the uploaded document. */
  artifactKey: z.string(),
  ref: z.string().optional(),
  commitSha: z.string().optional(),
});
export type IngestSbomRequest = z.infer<typeof IngestSbomRequest>;

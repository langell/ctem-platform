import { z } from 'zod';
import { Asset } from './domain/asset';
import { Finding } from './domain/finding';
import { RawFinding } from './domain/finding';
import { ScanJob, ScanJobResult } from './domain/scan';

/**
 * NATS subject layout: `ctem.<domain>.<event>`. Streams are bound per domain so
 * a noisy scanner stream can be scaled or replayed without touching the rest.
 */
export const SUBJECTS = {
  assetDiscovered: 'ctem.asset.discovered',
  assetUpdated: 'ctem.asset.updated',
  assetArchived: 'ctem.asset.archived',

  scanRequested: 'ctem.scan.requested',
  scanJobDispatched: 'ctem.scan.job.dispatched',
  scanJobCompleted: 'ctem.scan.job.completed',
  scanCompleted: 'ctem.scan.completed',

  findingsReported: 'ctem.finding.reported',
  findingCreated: 'ctem.finding.created',
  findingUpdated: 'ctem.finding.updated',
  findingResolved: 'ctem.finding.resolved',
  findingStateChanged: 'ctem.finding.state_changed',

  riskRescoreRequested: 'ctem.risk.rescore_requested',
  vulnPackagesObserved: 'ctem.risk.vuln_packages_observed',
  policyViolated: 'ctem.policy.violated',
  slaBreached: 'ctem.policy.sla_breached',

  notificationRequested: 'ctem.notification.requested',
} as const;

export type Subject = (typeof SUBJECTS)[keyof typeof SUBJECTS];

/** Per-domain JetStream streams; subjects above map onto these. */
export const STREAMS = {
  ASSETS: { name: 'CTEM_ASSETS', subjects: ['ctem.asset.>'] },
  SCANS: { name: 'CTEM_SCANS', subjects: ['ctem.scan.>'] },
  FINDINGS: { name: 'CTEM_FINDINGS', subjects: ['ctem.finding.>'] },
  RISK: { name: 'CTEM_RISK', subjects: ['ctem.risk.>', 'ctem.policy.>'] },
  NOTIFY: { name: 'CTEM_NOTIFY', subjects: ['ctem.notification.>'] },
} as const;

/** Every message on the bus carries tenancy and causation metadata. */
export const EventEnvelope = z.object({
  id: z.string().uuid(),
  subject: z.string(),
  orgId: z.string().uuid(),
  occurredAt: z.coerce.date(),
  traceId: z.string(),
  causationId: z.string().nullable().default(null),
  /** Bump when a payload shape changes so consumers can branch instead of crash. */
  version: z.number().int().default(1),
  producer: z.string(),
  payload: z.unknown(),
});
export type EventEnvelope<T = unknown> = Omit<z.infer<typeof EventEnvelope>, 'payload'> & {
  payload: T;
};

export const ScanRequestedPayload = z.object({
  scanId: z.string().uuid(),
  scannerType: z.string(),
  assetSelector: z.record(z.unknown()),
  options: z.record(z.unknown()).default({}),
});

export const FindingsReportedPayload = z.object({
  scanId: z.string().uuid(),
  jobId: z.string().uuid(),
  assetId: z.string().uuid(),
  scannerType: z.string(),
  artifactKey: z.string().nullable(),
  findings: z.array(RawFinding),
});
export type FindingsReportedPayload = z.infer<typeof FindingsReportedPayload>;

/**
 * A scanner matched these packages against a live feed because the local
 * mirror has never seen them. The feed ingester mirrors them so the next scan
 * is served locally.
 */
export const VulnPackagesObservedPayload = z.object({
  packages: z
    .array(z.object({ ecosystem: z.string().min(1), name: z.string().min(1) }))
    .min(1)
    .max(500),
});
export type VulnPackagesObservedPayload = z.infer<typeof VulnPackagesObservedPayload>;

export const PolicyViolatedPayload = z.object({
  findingId: z.string().uuid(),
  policyId: z.string().uuid(),
  actions: z.array(z.string()),
});

export const NotificationRequestedPayload = z.object({
  channel: z.enum(['slack', 'email', 'webhook', 'jira', 'servicenow', 'github_issue']),
  template: z.string(),
  target: z.string(),
  data: z.record(z.unknown()),
});

/** Payload schema per subject — used by the events lib to validate on publish and consume. */
export const EVENT_SCHEMAS = {
  [SUBJECTS.assetDiscovered]: Asset,
  [SUBJECTS.assetUpdated]: Asset,
  [SUBJECTS.assetArchived]: z.object({ assetId: z.string().uuid() }),
  [SUBJECTS.scanRequested]: ScanRequestedPayload,
  [SUBJECTS.scanJobDispatched]: ScanJob,
  [SUBJECTS.scanJobCompleted]: ScanJobResult,
  [SUBJECTS.scanCompleted]: z.object({ scanId: z.string().uuid(), status: z.string() }),
  [SUBJECTS.findingsReported]: FindingsReportedPayload,
  [SUBJECTS.findingCreated]: Finding,
  [SUBJECTS.findingUpdated]: Finding,
  [SUBJECTS.findingResolved]: Finding,
  [SUBJECTS.findingStateChanged]: z.object({
    findingId: z.string().uuid(),
    from: z.string(),
    to: z.string(),
    actor: z.string(),
  }),
  [SUBJECTS.riskRescoreRequested]: z.object({ findingIds: z.array(z.string().uuid()) }),
  [SUBJECTS.vulnPackagesObserved]: VulnPackagesObservedPayload,
  [SUBJECTS.policyViolated]: PolicyViolatedPayload,
  [SUBJECTS.slaBreached]: z.object({ findingId: z.string().uuid(), dueAt: z.coerce.date() }),
  [SUBJECTS.notificationRequested]: NotificationRequestedPayload,
} as const;

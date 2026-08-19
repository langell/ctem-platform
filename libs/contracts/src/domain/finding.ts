import { z } from 'zod';
import { AuditMeta, OrgId, Severity } from '../common';
import { ScannerType } from './scan';

/**
 * A raw finding is what a scanner emits. The findings service normalizes and
 * dedups raw findings into a `Finding`, which is the object humans triage.
 */
export const RawFinding = z.object({
  /** Scanner-local stable identity used for dedup across runs of the same scanner. */
  externalId: z.string(),
  scannerType: ScannerType,
  scannerName: z.string(),
  title: z.string(),
  description: z.string().default(''),
  severity: Severity,
  /** CVE / GHSA / CWE / rule id. */
  identifiers: z.array(z.object({ system: z.string(), value: z.string() })).default([]),
  cvssVector: z.string().nullable().default(null),
  cvssScore: z.number().min(0).max(10).nullable().default(null),
  epssScore: z.number().min(0).max(1).nullable().default(null),
  kev: z.boolean().default(false),
  location: z
    .object({
      path: z.string().optional(),
      startLine: z.number().int().optional(),
      endLine: z.number().int().optional(),
      packageName: z.string().optional(),
      packageVersion: z.string().optional(),
      packageEcosystem: z.string().optional(),
      purl: z.string().optional(),
      imageLayer: z.string().optional(),
      resource: z.string().optional(),
      port: z.number().int().optional(),
      url: z.string().optional(),
    })
    .default({}),
  fix: z
    .object({
      available: z.boolean().default(false),
      fixedVersion: z.string().optional(),
      guidance: z.string().optional(),
    })
    .default({ available: false }),
  /** Transitive dependency path, call path, or attack path evidence. */
  evidence: z.record(z.unknown()).default({}),
  raw: z.record(z.unknown()).default({}),
});
export type RawFinding = z.infer<typeof RawFinding>;

export const FindingState = z.enum([
  'open',
  'triaged',
  'in_progress',
  'resolved',
  'risk_accepted',
  'false_positive',
  'suppressed',
]);
export type FindingState = z.infer<typeof FindingState>;

/** Validation is the CTEM step Snyk/Veracode mostly skip: is this exposure actually exploitable here? */
export const ValidationVerdict = z.enum([
  'not_validated',
  'reachable',
  'not_reachable',
  'exploitable',
  'not_exploitable',
  'compensating_control',
]);
export type ValidationVerdict = z.infer<typeof ValidationVerdict>;

export const Finding = z
  .object({
    id: z.string().uuid(),
    orgId: OrgId,
    assetId: z.string().uuid(),
    /** Content hash across (asset, scannerType, externalId, location) — the dedup key. */
    fingerprint: z.string(),
    scannerType: ScannerType,
    title: z.string(),
    description: z.string(),
    severity: Severity,
    /** 0-100 composite: severity x exploitability x exposure x business criticality. */
    riskScore: z.number().min(0).max(100).default(0),
    state: FindingState.default('open'),
    validation: ValidationVerdict.default('not_validated'),
    identifiers: z.array(z.object({ system: z.string(), value: z.string() })).default([]),
    cvssScore: z.number().nullable().default(null),
    epssScore: z.number().nullable().default(null),
    kev: z.boolean().default(false),
    location: z.record(z.unknown()).default({}),
    fixAvailable: z.boolean().default(false),
    fixedVersion: z.string().nullable().default(null),
    slaDueAt: z.coerce.date().nullable().default(null),
    firstSeenAt: z.coerce.date(),
    lastSeenAt: z.coerce.date(),
    resolvedAt: z.coerce.date().nullable().default(null),
    ticketRef: z.string().nullable().default(null),
  })
  .merge(AuditMeta);
export type Finding = z.infer<typeof Finding>;

export const ListFindingsQuery = z.object({
  assetId: z.string().uuid().optional(),
  scannerType: ScannerType.optional(),
  severity: Severity.optional(),
  state: FindingState.optional(),
  validation: ValidationVerdict.optional(),
  minRiskScore: z.coerce.number().min(0).max(100).optional(),
  fixAvailable: z.coerce.boolean().optional(),
  slaBreached: z.coerce.boolean().optional(),
  q: z.string().optional(),
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});
export type ListFindingsQuery = z.infer<typeof ListFindingsQuery>;

export const TriageFindingRequest = z.object({
  state: FindingState,
  reason: z.string().min(1).max(2000),
  /** Required when moving to risk_accepted; enforced by the policy service. */
  expiresAt: z.coerce.date().optional(),
});
export type TriageFindingRequest = z.infer<typeof TriageFindingRequest>;

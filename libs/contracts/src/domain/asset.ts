import { z } from 'zod';
import { AuditMeta, OrgId } from '../common';

/**
 * The asset graph is the spine of CTEM. Every finding hangs off an asset, and
 * business context (criticality, owner, exposure) is what turns a raw CVE into
 * a prioritized exposure.
 */
export const AssetKind = z.enum([
  'repository',
  'package', // a released artifact / library the org publishes
  'container_image',
  'cloud_resource',
  'kubernetes_workload',
  'host',
  'domain',
  'ip_range',
  'web_application',
  'api_endpoint',
  'saas_app',
  'iac_stack',
]);
export type AssetKind = z.infer<typeof AssetKind>;

export const ExposureClass = z.enum(['internet_facing', 'internal', 'isolated', 'unknown']);
export const BusinessCriticality = z.enum(['tier0', 'tier1', 'tier2', 'tier3', 'unknown']);
export const DataClassification = z.enum(['pii', 'phi', 'pci', 'secrets', 'public', 'unknown']);

export const AssetSource = z.enum([
  'github',
  'gitlab',
  'bitbucket',
  'aws',
  'azure',
  'gcp',
  'kubernetes',
  'ecr',
  'dockerhub',
  'dns_enum',
  'cert_transparency',
  'port_scan',
  'manual',
  'api',
]);

export const Asset = z
  .object({
    id: z.string().uuid(),
    orgId: OrgId,
    kind: AssetKind,
    /** Stable dedup key, e.g. `github:acme/api`, `image:ghcr.io/acme/api@sha256:...`. */
    externalKey: z.string().min(1),
    name: z.string().min(1),
    source: AssetSource,
    exposure: ExposureClass.default('unknown'),
    criticality: BusinessCriticality.default('unknown'),
    dataClasses: z.array(DataClassification).default([]),
    // Nullable, not optional: the columns are `String?` and Prisma returns null.
    ownerTeam: z.string().nullable().default(null),
    ownerEmail: z.string().email().nullable().default(null),
    tags: z.record(z.string()).default({}),
    /** Raw connector payload, kept verbatim for re-normalization without a re-scan. */
    attributes: z.record(z.unknown()).default({}),
    firstSeenAt: z.coerce.date(),
    lastSeenAt: z.coerce.date(),
    archivedAt: z.coerce.date().nullable().default(null),
  })
  .merge(AuditMeta);
export type Asset = z.infer<typeof Asset>;

/** Typed edges let us answer "is this vulnerable package actually reachable from the internet?" */
export const AssetEdgeKind = z.enum([
  'deploys_to',
  'depends_on',
  'built_from',
  'runs_on',
  'exposes',
  'resolves_to',
  'owned_by',
]);

export const AssetEdge = z.object({
  id: z.string().uuid(),
  orgId: OrgId,
  fromAssetId: z.string().uuid(),
  toAssetId: z.string().uuid(),
  kind: AssetEdgeKind,
  confidence: z.number().min(0).max(1).default(1),
});
export type AssetEdge = z.infer<typeof AssetEdge>;

export const UpsertAssetRequest = Asset.pick({
  kind: true,
  externalKey: true,
  name: true,
  source: true,
}).extend({
  exposure: ExposureClass.optional(),
  criticality: BusinessCriticality.optional(),
  dataClasses: z.array(DataClassification).optional(),
  ownerTeam: z.string().optional(),
  ownerEmail: z.string().email().optional(),
  tags: z.record(z.string()).optional(),
  attributes: z.record(z.unknown()).optional(),
});
export type UpsertAssetRequest = z.infer<typeof UpsertAssetRequest>;

export const ListAssetsQuery = z.object({
  kind: AssetKind.optional(),
  exposure: ExposureClass.optional(),
  criticality: BusinessCriticality.optional(),
  ownerTeam: z.string().optional(),
  q: z.string().optional(),
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});
export type ListAssetsQuery = z.infer<typeof ListAssetsQuery>;

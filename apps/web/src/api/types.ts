/** Shapes the UI reads from the gateway. No derived scoring or tenancy logic. */

export interface Session {
  userId: string;
  orgId: string;
  role: string;
  permissions: string[];
  serviceAccount: string | null;
}

export interface Page<T> {
  items: T[];
  nextCursor: string | null;
}

export interface Asset {
  id: string;
  kind: string;
  name: string;
  source: string;
  exposure: string;
  criticality: string;
  ownerTeam: string | null;
  externalKey: string;
}

export interface Finding {
  id: string;
  assetId: string;
  title: string;
  description: string;
  severity: string;
  riskScore: number;
  state: string;
  validation: string;
  scannerType: string;
  cvssScore: number | null;
  epssScore: number | null;
  kev: boolean;
  fixAvailable: boolean;
  fixedVersion: string | null;
  location: Record<string, unknown>;
  evidence: {
    reachability?: 'reachable' | 'not_reachable' | 'unknown' | string;
    dependencyPath?: string[];
    [key: string]: unknown;
  };
  asset?: Asset;
}

export interface RiskExplanation {
  findingId: string;
  score: number;
  factors: Array<{
    name: string;
    weight: number;
    rawValue: number;
    contribution: number;
    note?: string;
  }>;
  matchedPolicies: string[];
}

export interface AssetGraph {
  nodes: Array<{
    id: string;
    name: string;
    kind: string;
    exposure: string;
    criticality: string;
  }>;
  edges: Array<{ from: string; to: string; kind: string; confidence: number }>;
}

export interface Scan {
  id: string;
  scannerType: string;
  status: string;
  trigger: string;
  jobsTotal: number;
  jobsCompleted: number;
  createdAt?: string;
}

export const SCANNER_TYPES = ['sca', 'sast', 'container', 'iac', 'secrets', 'asm', 'cloud_posture'] as const;
export type ScannerType = (typeof SCANNER_TYPES)[number];

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const EDITOR_ACTIONS = ['notify', 'ticket'] as const;
export type EditorAction = (typeof EDITOR_ACTIONS)[number];

/** Tenant-authored rule. This slice writes notify and/or ticket. */
export interface Policy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  condition: {
    severityAtLeast?: string;
    minRiskScore?: number;
    kevOnly?: boolean;
    minEpss?: number;
    requireFixAvailable?: boolean;
    scannerTypes?: string[];
    assetKinds?: string[];
    exposure?: string[];
    criticality?: string[];
  };
  actions: string[];
  slaHours: number | null;
}

export interface PolicyWrite {
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  condition: Policy['condition'];
  actions: EditorAction[];
  slaHours: number | null;
}

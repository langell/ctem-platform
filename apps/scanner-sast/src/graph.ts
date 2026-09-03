export type SastReachability = 'reachable' | 'not_reachable' | 'unknown';

export interface SastDataflowStep {
  path: string;
  line: number;
  label: 'source' | 'propagator' | 'sink';
}

export interface SastTaintFlow {
  source: { path: string; line: number; kind: string };
  sink: { path: string; line: number; kind: string };
  path: SastDataflowStep[];
}

export interface SastCallSite {
  path: string;
  line: number;
  callee: string;
}

/**
 * Import/call + taint/dataflow graph over first-party source in the clone.
 *
 * `reachable` / `not_reachable` on a SAST finding come from this object, not
 * from lockfile or manifest presence. A missing graph is a failed analysis.
 */
export interface SastGraph {
  files: Set<string>;
  imports: Map<string, Set<string>>;
  calls: SastCallSite[];
  taintFlows: SastTaintFlow[];
  truncated: boolean;
}

export class SastAnalysisError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SastAnalysisError';
  }
}

export function emptySastGraph(): SastGraph {
  return {
    files: new Set(),
    imports: new Map(),
    calls: [],
    taintFlows: [],
    truncated: false,
  };
}

export function isSastGraph(value: unknown): value is SastGraph {
  if (value === null || typeof value !== 'object') return false;
  const graph = value as SastGraph;
  return (
    graph.files instanceof Set &&
    graph.imports instanceof Map &&
    Array.isArray(graph.calls) &&
    Array.isArray(graph.taintFlows) &&
    typeof graph.truncated === 'boolean'
  );
}

export function serializeSastGraph(graph: SastGraph): Record<string, unknown> {
  return {
    files: [...graph.files],
    imports: Object.fromEntries([...graph.imports].map(([file, specs]) => [file, [...specs]])),
    calls: graph.calls,
    taintFlows: graph.taintFlows,
    truncated: graph.truncated,
  };
}

/**
 * Taint-informed verdict. Injection sinks with a source→sink flow are
 * reachable. An analyzed file with no such flow is not_reachable. Secrets
 * and anything the graph cannot prove stay unknown — after a graph exists.
 */
export function verdictForMatch(
  match: { ruleId: string; path: string; startLine: number },
  graph: SastGraph,
): SastReachability {
  const flow = graph.taintFlows.find(
    (f) => f.sink.path === match.path && Math.abs(f.sink.line - match.startLine) <= 1,
  );
  if (flow) return 'reachable';
  if (match.ruleId === 'ctem.hardcoded-secret') return 'unknown';
  if (graph.truncated) return 'unknown';
  if (graph.files.has(match.path)) return 'not_reachable';
  return 'unknown';
}

import type { ResolvedComponent } from '../sbom.parser';

export const REACHABILITY_VERDICTS = ['reachable', 'not_reachable', 'unknown'] as const;
export type ReachabilityVerdict = (typeof REACHABILITY_VERDICTS)[number];

export const REACHABILITY_LANGUAGES = ['javascript', 'python', 'go'] as const;
export type ReachabilityLanguage = (typeof REACHABILITY_LANGUAGES)[number];

/**
 * Import/call graph produced from first-party source in the cloned workDir.
 *
 * `reachable` / `not_reachable` are only assigned from this object. A missing
 * graph is a failed analysis, not an all-unknown success.
 */
export interface ReachabilityGraph {
  /** Languages for which at least one first-party source file was parsed. */
  languages: Set<ReachabilityLanguage>;
  /** Package names (or Go import paths) referenced by first-party code. */
  imported: Map<ReachabilityLanguage, Set<string>>;
  /** Languages with unresolved dynamic imports — cannot prove not_reachable. */
  ambiguous: Set<ReachabilityLanguage>;
  /** Walk or read was incomplete (cap, skipped file). Unproven packages stay unknown. */
  truncated: boolean;
}

export class ReachabilityAnalysisError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReachabilityAnalysisError';
  }
}

export function emptyReachabilityGraph(): ReachabilityGraph {
  return {
    languages: new Set(),
    imported: new Map(),
    ambiguous: new Set(),
    truncated: false,
  };
}

export function isReachabilityGraph(value: unknown): value is ReachabilityGraph {
  if (value === null || typeof value !== 'object') return false;
  const graph = value as ReachabilityGraph;
  return (
    graph.languages instanceof Set &&
    graph.imported instanceof Map &&
    graph.ambiguous instanceof Set &&
    typeof graph.truncated === 'boolean'
  );
}

const ECOSYSTEM_LANGUAGE: Record<string, ReachabilityLanguage> = {
  npm: 'javascript',
  PyPI: 'python',
  Go: 'go',
};

export function languageForEcosystem(ecosystem: string): ReachabilityLanguage | undefined {
  return ECOSYSTEM_LANGUAGE[ecosystem];
}

export function normalizePyName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

/**
 * Verdict from a produced graph. Lockfile presence is not an input.
 *
 * - imported by first-party code → reachable
 * - language covered, no import, not ambiguous/truncated → not_reachable
 * - anything the graph cannot prove → unknown
 */
export function verdictForComponent(
  component: Pick<ResolvedComponent, 'name' | 'ecosystem'>,
  graph: ReachabilityGraph,
): ReachabilityVerdict {
  const language = languageForEcosystem(component.ecosystem);
  if (!language || !graph.languages.has(language)) return 'unknown';

  const imported = graph.imported.get(language) ?? new Set();
  if (isImported(component.name, component.ecosystem, imported)) return 'reachable';
  if (graph.truncated || graph.ambiguous.has(language)) return 'unknown';
  return 'not_reachable';
}

function isImported(name: string, ecosystem: string, imported: Set<string>): boolean {
  if (ecosystem === 'Go') {
    for (const path of imported) {
      if (path === name || path.startsWith(`${name}/`)) return true;
    }
    return false;
  }
  if (ecosystem === 'PyPI') {
    return imported.has(normalizePyName(name));
  }
  return imported.has(name);
}

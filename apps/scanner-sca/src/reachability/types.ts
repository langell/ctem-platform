import type { ResolvedComponent } from '../sbom.parser';

export const REACHABILITY_VERDICTS = ['reachable', 'not_reachable', 'unknown'] as const;
export type ReachabilityVerdict = (typeof REACHABILITY_VERDICTS)[number];

export const REACHABILITY_LANGUAGES = ['javascript', 'python', 'go', 'rust'] as const;
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
  /** Package names (Go import paths, or Rust crate idents) referenced by first-party code. */
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
  'crates.io': 'rust',
};

export function languageForEcosystem(ecosystem: string): ReachabilityLanguage | undefined {
  return ECOSYSTEM_LANGUAGE[ecosystem];
}

export function normalizePyName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

/** crates.io package ids and Rust idents: case-insensitive, `-` matches `_`. */
export function normalizeRustCrate(name: string): string {
  return name.toLowerCase().replace(/-/g, '_');
}

/**
 * Package name (normalized) → rustc library ident, when those differ.
 * Fixed table only — no network lookup of lib names.
 */
const RUST_LIB_ALIASES: Readonly<Record<string, string>> = {
  xml_rs: 'xml',
  md_5: 'md5',
  sha_1: 'sha1',
  rust_crypto: 'crypto',
  rust_ini: 'ini',
  rust_s3: 's3',
};

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
  if (language === 'rust' && rustPackageMayDifferFromLib(component.name)) return 'unknown';
  return 'not_reachable';
}

/** `xml-rs`, `md-5`, `rust-crypto`, and the same shapes: lib name may not be the package id. */
function rustPackageMayDifferFromLib(name: string): boolean {
  const hyphenated = name.toLowerCase().replace(/_/g, '-');
  const underscored = name.toLowerCase().replace(/-/g, '_');
  return (
    /^rust-/.test(hyphenated) ||
    /-rs$/.test(hyphenated) ||
    /-\d+$/.test(hyphenated) ||
    /^rust_/.test(underscored) ||
    /_rs$/.test(underscored) ||
    /_\d+$/.test(underscored)
  );
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
  if (ecosystem === 'crates.io') return rustCrateImported(name, imported);
  return imported.has(name);
}

function rustCrateImported(name: string, imported: Set<string>): boolean {
  const needle = normalizeRustCrate(name);
  if (rustImportHas(imported, needle)) return true;
  const alias = RUST_LIB_ALIASES[needle];
  return alias !== undefined && rustImportHas(imported, normalizeRustCrate(alias));
}

function rustImportHas(imported: Set<string>, needle: string): boolean {
  for (const importedName of imported) {
    if (normalizeRustCrate(importedName) === needle) return true;
  }
  return false;
}

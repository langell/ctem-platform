import { nameFromNodeId, nodeId, shortestPathsFromRoots } from './graph';
import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const pipfileParser: EcosystemParser = {
  id: 'pipenv',
  ecosystem: ECOSYSTEM.pypi,
  group: 'python',
  priority: 25,
  matches: (fileName) => fileName === 'Pipfile.lock',
  companionFiles: ['Pipfile'],
  parse: (input) => parsePipfileLock(input.content, input.relPath, input.companions['Pipfile']),
};

interface LockEntry {
  version?: string;
  dependencies?: Record<string, unknown> | string[];
  git?: string;
  path?: string;
  file?: string;
  editable?: boolean;
}

/**
 * Versions come from Pipfile.lock category maps (`default`, `develop`, …).
 * Direct names come from Pipfile `[packages]` / `[dev-packages]` when present.
 * Edges come from a package's `dependencies` map/list when the lock wrote one;
 * otherwise packages that nothing else depends on (or the Pipfile set) are
 * treated as direct — same fallback as poetry without pyproject.toml.
 */
export function parsePipfileLock(content: string, manifestPath: string, pipfile?: string) {
  const doc = JSON.parse(content) as Record<string, unknown>;
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error('Pipfile.lock is not an object');
  }

  const packages: Array<{ name: string; version: string; deps: string[] }> = [];
  for (const [key, value] of Object.entries(doc)) {
    if (key === '_meta' || !value || typeof value !== 'object' || Array.isArray(value)) continue;
    for (const [name, raw] of Object.entries(value as Record<string, LockEntry>)) {
      if (!raw || typeof raw !== 'object') continue;
      const version = pinnedLockVersion(raw.version);
      if (!version) continue;
      packages.push({ name, version, deps: lockDepNames(raw.dependencies) });
    }
  }

  const byName = new Map(packages.map((p) => [normalizePy(p.name), p]));
  const edges = new Map<string, string[]>();
  for (const pkg of packages) {
    edges.set(
      nodeId(pkg.name, pkg.version),
      pkg.deps
        .map((d) => byName.get(normalizePy(d)))
        .filter(Boolean)
        .map((d) => nodeId(d!.name, d!.version)),
    );
  }

  const declaredDirect = directFromPipfile(pipfile);
  const hasEdges = [...edges.values()].some((deps) => deps.length > 0);
  const directIds =
    declaredDirect.size > 0
      ? packages.filter((p) => declaredDirect.has(normalizePy(p.name))).map((p) => nodeId(p.name, p.version))
      : hasEdges
        ? [...edges.keys()].filter((id) => ![...edges.values()].some((deps) => deps.includes(id)))
        : packages.map((p) => nodeId(p.name, p.version));

  const paths = shortestPathsFromRoots(directIds, edges);

  return packages.map((pkg) => {
    const id = nodeId(pkg.name, pkg.version);
    const direct = directIds.includes(id);
    return makeComponent({
      name: pkg.name,
      version: pkg.version,
      ecosystem: ECOSYSTEM.pypi,
      purl: purlFor(ECOSYSTEM.pypi, pkg.name, pkg.version),
      direct,
      dependencyPath: paths.get(id)?.map(nameFromNodeId) ?? (direct ? [pkg.name] : []),
      manifestPath,
    });
  });
}

function pinnedLockVersion(version?: string): string | null {
  if (!version) return null;
  const stripped = version.trim().replace(/^===?/, '');
  return stripped || null;
}

function lockDepNames(deps?: Record<string, unknown> | string[]): string[] {
  if (!deps) return [];
  if (Array.isArray(deps)) {
    return deps.filter((d): d is string => typeof d === 'string' && d.length > 0);
  }
  return Object.keys(deps);
}

function directFromPipfile(source?: string): Set<string> {
  const out = new Set<string>();
  if (!source) return out;
  const sections = source.split(/\n(?=\[)/);
  for (const section of sections) {
    const header = section.match(/^\[([^\]]+)\]/)?.[1] ?? '';
    if (header !== 'packages' && header !== 'dev-packages') continue;
    for (const line of section.split('\n').slice(1)) {
      const m = /^\s*([A-Za-z0-9_.-]+)\s*=/.exec(line);
      if (m) out.add(normalizePy(m[1]));
    }
  }
  return out;
}

function normalizePy(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

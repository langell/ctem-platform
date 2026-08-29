import { nameFromNodeId, nodeId, shortestPathsFromRoots } from './graph';
import { tomlString, splitTomlTables } from './cargo';
import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const poetryParser: EcosystemParser = {
  id: 'poetry',
  ecosystem: ECOSYSTEM.pypi,
  group: 'python',
  priority: 30,
  matches: (fileName) => fileName === 'poetry.lock',
  companionFiles: ['pyproject.toml'],
  parse: (input) => parsePoetryLock(input.content, input.relPath, input.companions['pyproject.toml']),
};

/**
 * Versions and the dependency graph come from poetry.lock. Direct vs transitive
 * uses `[tool.poetry.dependencies]` / `[tool.poetry.group.*.dependencies]` in
 * pyproject.toml when present; otherwise packages that nothing else depends on
 * are treated as direct.
 */
export function parsePoetryLock(content: string, manifestPath: string, pyproject?: string) {
  const packages = splitTomlTables(content, 'package')
    .map((block) => {
      const name = tomlString(block, 'name');
      const version = tomlString(block, 'version');
      if (!name || !version) return null;
      return { name, version, deps: poetryDepNames(block) };
    })
    .filter(Boolean) as Array<{ name: string; version: string; deps: string[] }>;

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

  const declaredDirect = directFromPyproject(pyproject);
  const directIds =
    declaredDirect.size > 0
      ? packages.filter((p) => declaredDirect.has(normalizePy(p.name))).map((p) => nodeId(p.name, p.version))
      : [...edges.keys()].filter((id) => ![...edges.values()].some((deps) => deps.includes(id)));

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

function poetryDepNames(block: string): string[] {
  const idx = block.search(/\[package\.dependencies\]/);
  if (idx === -1) return [];
  const rest = block.slice(idx).split(/\n\[/)[0];
  const names: string[] = [];
  for (const line of rest.split('\n').slice(1)) {
    const m = /^\s*([A-Za-z0-9_.-]+)\s*=/.exec(line);
    if (m) names.push(m[1]);
  }
  return names;
}

function directFromPyproject(source?: string): Set<string> {
  const out = new Set<string>();
  if (!source) return out;
  // [tool.poetry.dependencies], [tool.poetry.dev-dependencies], [tool.poetry.group.*.dependencies]
  const sections = source.split(/\n(?=\[)/);
  for (const section of sections) {
    const header = section.match(/^\[([^\]]+)\]/)?.[1] ?? '';
    if (!/tool\.poetry\.(dependencies|dev-dependencies|group\.[^.]+\.dependencies)$/.test(header)) {
      continue;
    }
    for (const line of section.split('\n').slice(1)) {
      const m = /^\s*([A-Za-z0-9_.-]+)\s*=/.exec(line);
      if (m && m[1] !== 'python') out.add(normalizePy(m[1]));
    }
  }
  return out;
}

function normalizePy(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

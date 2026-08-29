import { nameFromNodeId, nodeId, shortestPathsFromRoots } from './graph';
import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const cargoParser: EcosystemParser = {
  id: 'cargo',
  ecosystem: ECOSYSTEM.cargo,
  group: 'cargo',
  priority: 10,
  matches: (fileName) => fileName === 'Cargo.lock',
  parse: (input) => parseCargoLock(input.content, input.relPath),
};

interface CargoPackage {
  name: string;
  version: string;
  source?: string;
  dependencies: Array<{ name: string; version?: string }>;
}

/**
 * Cargo.lock is TOML. We parse `[[package]]` tables only — enough for the
 * resolved graph, without a general TOML library.
 *
 * Root/workspace members have no `source` and are omitted from findings
 * (they are first-party). Their `dependencies` are the direct set.
 */
export function parseCargoLock(content: string, manifestPath: string) {
  const packages = splitTomlTables(content, 'package').map(parseCargoPackage).filter(Boolean) as CargoPackage[];
  if (!packages.length) return [];

  const byName = new Map<string, CargoPackage[]>();
  for (const pkg of packages) {
    const list = byName.get(pkg.name) ?? [];
    list.push(pkg);
    byName.set(pkg.name, list);
  }

  const resolveDep = (dep: { name: string; version?: string }): CargoPackage | undefined => {
    const candidates = byName.get(dep.name) ?? [];
    if (dep.version) {
      return candidates.find((c) => c.version === dep.version) ?? candidates[0];
    }
    return candidates[0];
  };

  const roots = packages.filter((p) => !p.source);
  const thirdParty = packages.filter((p) => p.source);
  const edges = new Map<string, string[]>();
  for (const pkg of packages) {
    const id = nodeId(pkg.name, pkg.version);
    edges.set(
      id,
      pkg.dependencies
        .map(resolveDep)
        .filter((d): d is CargoPackage => Boolean(d?.source))
        .map((d) => nodeId(d.name, d.version)),
    );
  }

  const directIds = new Set<string>();
  for (const root of roots) {
    for (const dep of root.dependencies) {
      const resolved = resolveDep(dep);
      if (resolved?.source) directIds.add(nodeId(resolved.name, resolved.version));
    }
  }
  // A standalone crate with no workspace member listed still has third-party packages.
  if (!directIds.size && !roots.length) {
    const referenced = new Set([...edges.values()].flat());
    for (const pkg of thirdParty) {
      const id = nodeId(pkg.name, pkg.version);
      if (!referenced.has(id)) directIds.add(id);
    }
  }

  const paths = shortestPathsFromRoots(directIds, edges);

  return thirdParty.map((pkg) => {
    const id = nodeId(pkg.name, pkg.version);
    const direct = directIds.has(id);
    return makeComponent({
      name: pkg.name,
      version: pkg.version,
      ecosystem: ECOSYSTEM.cargo,
      purl: purlFor(ECOSYSTEM.cargo, pkg.name, pkg.version),
      direct,
      dependencyPath: paths.get(id)?.map(nameFromNodeId) ?? (direct ? [pkg.name] : []),
      manifestPath,
    });
  });
}

function parseCargoPackage(block: string): CargoPackage | null {
  const name = tomlString(block, 'name');
  const version = tomlString(block, 'version');
  if (!name || !version) return null;
  const source = tomlString(block, 'source');
  const depsBlock = block.match(/dependencies\s*=\s*\[([\s\S]*?)\]/)?.[1] ?? '';
  const dependencies = [...depsBlock.matchAll(/"([^"]+)"/g)].map((m) => {
    const parts = m[1].split(/\s+/);
    return { name: parts[0], version: parts[1] };
  });
  return { name, version, source: source ?? undefined, dependencies };
}

export function splitTomlTables(content: string, name: string): string[] {
  const marker = `[[${name}]]`;
  const parts = content.split(marker).slice(1);
  return parts.map((part) => {
    const next = part.search(/\n\[\[/);
    return next === -1 ? part : part.slice(0, next);
  });
}

export function tomlString(block: string, key: string): string | null {
  const m = new RegExp(`^\\s*${key}\\s*=\\s*"([^"]*)"`, 'm').exec(block);
  return m?.[1] ?? null;
}

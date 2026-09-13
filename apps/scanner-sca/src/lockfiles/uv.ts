import { splitTomlTables, tomlString } from './cargo';
import { nameFromNodeId, nodeId, shortestPathsFromRoots } from './graph';
import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const uvParser: EcosystemParser = {
  id: 'uv',
  ecosystem: ECOSYSTEM.pypi,
  group: 'python',
  priority: 26,
  matches: (fileName) => fileName === 'uv.lock',
  parse: (input) => parseUvLock(input.content, input.relPath),
};

interface UvPackage {
  name: string;
  version: string;
  firstParty: boolean;
  deps: Array<{ name: string; version?: string }>;
}

/**
 * Versions and edges come from `[[package]]` tables. Workspace roots
 * (`source = { virtual|editable|directory = … }`, or no source) are omitted
 * from findings — their `dependencies` / `[package.dev-dependencies]` /
 * `[package.dependency-groups]` are the direct set. Same shape as Cargo.lock.
 */
export function parseUvLock(content: string, manifestPath: string) {
  if (content.trim() && !content.includes('[[package]]') && !/^\s*version\s*=/m.test(content)) {
    throw new Error('uv.lock is missing [[package]] tables');
  }

  const packages = splitTomlTables(content, 'package')
    .map(parseUvPackage)
    .filter((p): p is UvPackage => Boolean(p));
  if (!packages.length) return [];

  const byName = new Map<string, UvPackage[]>();
  for (const pkg of packages) {
    const key = normalizePy(pkg.name);
    const list = byName.get(key) ?? [];
    list.push(pkg);
    byName.set(key, list);
  }

  const resolveDep = (dep: { name: string; version?: string }): UvPackage | undefined => {
    const candidates = (byName.get(normalizePy(dep.name)) ?? []).filter((c) => !c.firstParty);
    if (dep.version) {
      return candidates.find((c) => c.version === dep.version) ?? candidates[0];
    }
    return candidates[0];
  };

  const roots = packages.filter((p) => p.firstParty);
  const thirdParty = packages.filter((p) => !p.firstParty);
  const edges = new Map<string, string[]>();
  for (const pkg of packages) {
    edges.set(
      nodeId(pkg.name, pkg.version),
      pkg.deps
        .map(resolveDep)
        .filter((d): d is UvPackage => Boolean(d))
        .map((d) => nodeId(d.name, d.version)),
    );
  }

  const directIds = new Set<string>();
  for (const root of roots) {
    for (const dep of root.deps) {
      const resolved = resolveDep(dep);
      if (resolved) directIds.add(nodeId(resolved.name, resolved.version));
    }
  }
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
      ecosystem: ECOSYSTEM.pypi,
      purl: purlFor(ECOSYSTEM.pypi, pkg.name, pkg.version),
      direct,
      dependencyPath: paths.get(id)?.map(nameFromNodeId) ?? (direct ? [pkg.name] : []),
      manifestPath,
    });
  });
}

function parseUvPackage(block: string): UvPackage | null {
  const name = tomlString(block, 'name');
  const version = tomlString(block, 'version');
  if (!name || !version) return null;
  const kind = uvSourceKind(block);
  const firstParty = kind === null || kind === 'virtual' || kind === 'editable' || kind === 'directory';
  return { name, version, firstParty, deps: uvDepRefs(block, firstParty) };
}

function uvSourceKind(block: string): string | null {
  return /^\s*source\s*=\s*\{\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=/m.exec(block)?.[1] ?? null;
}

function uvDepRefs(block: string, firstParty: boolean): Array<{ name: string; version?: string }> {
  const deps = parseInlineDepArray(headerBeforeSection(block));
  if (!firstParty) return deps;

  const extra = [sectionBody(block, 'package.dev-dependencies'), sectionBody(block, 'package.dependency-groups')]
    .filter(Boolean)
    .flatMap((section) => [...section.matchAll(/\{\s*name\s*=\s*"([^"]+)"/g)].map((m) => ({ name: m[1] })));
  return [...deps, ...extra];
}

function headerBeforeSection(block: string): string {
  const idx = block.search(/\n\[/);
  return idx === -1 ? block : block.slice(0, idx);
}

function sectionBody(block: string, header: string): string {
  const marker = `[${header}]`;
  const idx = block.indexOf(marker);
  if (idx === -1) return '';
  const rest = block.slice(idx + marker.length);
  const end = rest.search(/\n\[package\./);
  return end === -1 ? rest : rest.slice(0, end);
}

function parseInlineDepArray(header: string): Array<{ name: string; version?: string }> {
  const depsBlock = header.match(/dependencies\s*=\s*\[([\s\S]*?)\]/)?.[1];
  if (!depsBlock) return [];
  const deps: Array<{ name: string; version?: string }> = [];
  for (const m of depsBlock.matchAll(/\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g)) {
    const name = /name\s*=\s*"([^"]+)"/.exec(m[1])?.[1];
    if (!name) continue;
    const version = /(?:^|[,\s])version\s*=\s*"([^"]+)"/.exec(m[1])?.[1];
    deps.push({ name, version: version ?? undefined });
  }
  return deps;
}

function normalizePy(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

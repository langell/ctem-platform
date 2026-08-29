import { parse as parseYaml } from 'yaml';
import { nameFromNodeId, nodeId, shortestPathsFromRoots } from './graph';
import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const pnpmParser: EcosystemParser = {
  id: 'pnpm',
  ecosystem: ECOSYSTEM.npm,
  group: 'javascript',
  priority: 30,
  matches: (fileName) => fileName === 'pnpm-lock.yaml',
  parse: (input) => parsePnpmLock(input.content, input.relPath),
};

interface PnpmLock {
  lockfileVersion?: string | number;
  importers?: Record<
    string,
    {
      dependencies?: Record<string, PnpmImporterDep>;
      devDependencies?: Record<string, PnpmImporterDep>;
      optionalDependencies?: Record<string, PnpmImporterDep>;
    }
  >;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  packages?: Record<string, PnpmPackage>;
  snapshots?: Record<string, { dependencies?: Record<string, string> }>;
}

interface PnpmImporterDep {
  specifier?: string;
  version?: string;
}

interface PnpmPackage {
  resolution?: { integrity?: string };
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  name?: string;
  version?: string;
}

export function parsePnpmLock(content: string, manifestPath: string) {
  const doc = parseYaml(content) as PnpmLock | null;
  if (!doc || typeof doc !== 'object') return [];

  const lockMajor = Number.parseInt(String(doc.lockfileVersion ?? '0'), 10);
  const packages = doc.packages ?? {};
  const snapshots = doc.snapshots ?? {};

  const resolved = new Map<string, { name: string; version: string }>();
  for (const key of [...Object.keys(packages), ...Object.keys(snapshots)]) {
    const parsed = splitPnpmKey(key);
    if (!parsed) continue;
    const id = nodeId(parsed.name, parsed.version);
    if (!resolved.has(id)) resolved.set(id, parsed);
  }

  const edges = new Map<string, string[]>();
  const depSource = lockMajor >= 9 ? snapshots : packages;
  for (const [key, value] of Object.entries(depSource)) {
    const parsed = splitPnpmKey(key);
    if (!parsed) continue;
    const id = nodeId(parsed.name, parsed.version);
    const deps = {
      ...(value?.dependencies ?? {}),
      ...((value as PnpmPackage).optionalDependencies ?? {}),
    };
    const next: string[] = [];
    for (const [depName, depVersion] of Object.entries(deps)) {
      const dep = resolvePnpmDep(depName, String(depVersion), resolved);
      if (dep) next.push(nodeId(dep.name, dep.version));
    }
    const existing = edges.get(id) ?? [];
    edges.set(id, [...new Set([...existing, ...next])]);
  }

  const directNames = new Set<string>();
  if (doc.importers) {
    for (const importer of Object.values(doc.importers)) {
      for (const name of [
        ...Object.keys(importer.dependencies ?? {}),
        ...Object.keys(importer.devDependencies ?? {}),
        ...Object.keys(importer.optionalDependencies ?? {}),
      ]) {
        directNames.add(name);
      }
    }
  } else {
    for (const name of [
      ...Object.keys(doc.dependencies ?? {}),
      ...Object.keys(doc.devDependencies ?? {}),
    ]) {
      directNames.add(name);
    }
  }

  const directIds = [...resolved.values()]
    .filter((p) => directNames.has(p.name))
    .map((p) => nodeId(p.name, p.version));
  const paths = shortestPathsFromRoots(directIds, edges);

  return [...resolved.values()].map((p) => {
    const id = nodeId(p.name, p.version);
    const direct = directNames.has(p.name);
    return makeComponent({
      name: p.name,
      version: p.version,
      ecosystem: ECOSYSTEM.npm,
      purl: purlFor(ECOSYSTEM.npm, p.name, p.version),
      direct,
      dependencyPath: paths.get(id)?.map(nameFromNodeId) ?? (direct ? [p.name] : []),
      manifestPath,
    });
  });
}

/**
 * Keys look like:
 *   express@4.18.2                          (v9)
 *   /express@4.18.2                         (v6)
 *   /express/4.18.2                         (v5)
 *   /@scope/name@1.0.0                      (v6 scoped)
 *   express@4.18.2(@types/node@18.0.0)      (peer suffix)
 */
export function splitPnpmKey(raw: string): { name: string; version: string } | null {
  let key = raw.replace(/^\//, '');
  const peer = key.indexOf('(');
  if (peer !== -1) key = key.slice(0, peer);

  if (key.startsWith('@')) {
    const at = key.lastIndexOf('@');
    if (at > 0) return { name: key.slice(0, at), version: key.slice(at + 1) };
    const parts = key.split('/');
    if (parts.length >= 3) {
      return { name: `${parts[0]}/${parts[1]}`, version: parts.slice(2).join('/') };
    }
    return null;
  }

  const at = key.lastIndexOf('@');
  if (at > 0) return { name: key.slice(0, at), version: key.slice(at + 1) };
  const slash = key.indexOf('/');
  if (slash > 0) return { name: key.slice(0, slash), version: key.slice(slash + 1) };
  return null;
}

function resolvePnpmDep(
  name: string,
  versionField: string,
  resolved: Map<string, { name: string; version: string }>,
): { name: string; version: string } | undefined {
  const fromKey = splitPnpmKey(versionField.startsWith('/') || versionField.includes('@') ? versionField : `${name}@${versionField}`);
  if (fromKey && resolved.has(nodeId(fromKey.name, fromKey.version))) return fromKey;
  const plain = nodeId(name, versionField);
  return resolved.get(plain);
}

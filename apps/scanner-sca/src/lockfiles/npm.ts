import { nameFromNodeId, nodeId, shortestPathsFromRoots } from './graph';
import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser, type LockfileInput } from './types';

interface NpmLockV2 {
  lockfileVersion?: number;
  packages?: Record<
    string,
    {
      name?: string;
      version?: string;
      resolved?: string;
      link?: boolean;
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    }
  >;
  dependencies?: Record<string, NpmLockV1Node>;
}

interface NpmLockV1Node {
  version?: string;
  resolved?: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, NpmLockV1Node>;
}

export const npmParser: EcosystemParser = {
  id: 'npm',
  ecosystem: ECOSYSTEM.npm,
  group: 'javascript',
  priority: 10,
  matches: (fileName) => fileName === 'package-lock.json',
  parse: (input) => parseNpmLock(input),
};

export function parseNpmLock(input: LockfileInput) {
  const doc = JSON.parse(input.content) as NpmLockV2;
  if (doc.packages && Object.keys(doc.packages).length) {
    return parseNpmV2(doc, input.relPath);
  }
  if (doc.dependencies) {
    return parseNpmV1(doc.dependencies, input.relPath);
  }
  return [];
}

function parseNpmV2(doc: NpmLockV2, manifestPath: string) {
  const packages = doc.packages ?? {};
  const keys = Object.keys(packages);
  const keySet = new Set(keys);

  const components: ReturnType<typeof makeComponent>[] = [];
  const edges = new Map<string, string[]>();
  const idByKey = new Map<string, string>();

  for (const key of keys) {
    // Workspace / first-party packages live at keys like `packages/foo`, not under node_modules/.
    if (!key.includes('node_modules/')) continue;
    const pkg = packages[key];
    if (!pkg?.version || pkg.link) continue;
    if (isLocalResolved(pkg.resolved)) continue;
    const name = pkg.name ?? nameFromLockKey(key);
    if (!name) continue;
    const id = nodeId(name, pkg.version);
    idByKey.set(key, id);
  }

  const root = packages[''] ?? {};
  const directNames = new Set([
    ...Object.keys(root.dependencies ?? {}),
    ...Object.keys(root.devDependencies ?? {}),
    ...Object.keys(root.optionalDependencies ?? {}),
  ]);
  // Workspace packages (keys without node_modules/) are additional roots.
  for (const key of keys) {
    if (!key || key.includes('node_modules/')) continue;
    const pkg = packages[key];
    for (const name of [
      ...Object.keys(pkg?.dependencies ?? {}),
      ...Object.keys(pkg?.devDependencies ?? {}),
      ...Object.keys(pkg?.optionalDependencies ?? {}),
    ]) {
      directNames.add(name);
    }
  }

  for (const [key, id] of idByKey) {
    const pkg = packages[key]!;
    const depNames = [
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.optionalDependencies ?? {}),
    ];
    const next: string[] = [];
    for (const depName of depNames) {
      const resolvedKey = resolveNodeModule(key, depName, keySet);
      const depId = resolvedKey ? idByKey.get(resolvedKey) : undefined;
      if (depId) next.push(depId);
    }
    edges.set(id, next);
  }

  const directIds = [...idByKey.values()].filter((id) => directNames.has(nameFromNodeId(id)));
  const paths = shortestPathsFromRoots(directIds, edges);

  const seen = new Set<string>();
  for (const [key, id] of idByKey) {
    if (seen.has(id)) continue;
    seen.add(id);
    const name = nameFromNodeId(id);
    const version = packages[key]!.version!;
    const direct = directNames.has(name);
    components.push(
      makeComponent({
        name,
        version,
        ecosystem: ECOSYSTEM.npm,
        purl: purlFor(ECOSYSTEM.npm, name, version),
        direct,
        dependencyPath: paths.get(id)?.map(nameFromNodeId) ?? (direct ? [name] : []),
        manifestPath,
      }),
    );
  }
  return components;
}

function parseNpmV1(tree: Record<string, NpmLockV1Node>, manifestPath: string) {
  const edges = new Map<string, string[]>();
  const versions = new Map<string, string>();
  const directs = new Set<string>();

  function walk(nodes: Record<string, NpmLockV1Node>, parentId: string | null): void {
    for (const [name, node] of Object.entries(nodes)) {
      if (!node.version || isLocalResolved(node.resolved)) continue;
      const id = nodeId(name, node.version);
      versions.set(id, node.version);
      if (parentId === null) directs.add(id);
      if (parentId) {
        const list = edges.get(parentId) ?? [];
        list.push(id);
        edges.set(parentId, list);
      }
      if (node.dependencies) walk(node.dependencies, id);
    }
  }

  walk(tree, null);
  const paths = shortestPathsFromRoots(directs, edges);

  return [...versions.entries()].map(([id, version]) => {
    const name = nameFromNodeId(id);
    const direct = directs.has(id);
    return makeComponent({
      name,
      version,
      ecosystem: ECOSYSTEM.npm,
      purl: purlFor(ECOSYSTEM.npm, name, version),
      direct,
      dependencyPath: paths.get(id)?.map(nameFromNodeId) ?? (direct ? [name] : []),
      manifestPath,
    });
  });
}

function nameFromLockKey(key: string): string {
  const marker = 'node_modules/';
  const i = key.lastIndexOf(marker);
  return i === -1 ? key : key.slice(i + marker.length);
}

function resolveNodeModule(fromKey: string, depName: string, keys: Set<string>): string | undefined {
  let current = fromKey;
  while (true) {
    const candidate = current ? `${current}/node_modules/${depName}` : `node_modules/${depName}`;
    if (keys.has(candidate)) return candidate;
    if (!current) return undefined;
    const i = current.lastIndexOf('/node_modules/');
    current = i === -1 ? '' : current.slice(0, i);
  }
}

function isLocalResolved(resolved?: string): boolean {
  if (!resolved) return false;
  return (
    resolved.startsWith('file:') ||
    resolved.startsWith('link:') ||
    resolved.startsWith('workspace:') ||
    resolved.startsWith('git+') ||
    resolved.startsWith('github:')
  );
}

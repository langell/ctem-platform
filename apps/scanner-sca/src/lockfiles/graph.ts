/**
 * BFS from the given roots. Each path includes the node itself
 * (a direct dep's path is `[name]`; a transitive dep is `[direct, …, name]`).
 * First visit wins, so diamond graphs get the shortest explanation.
 */
export function shortestPathsFromRoots(
  roots: Iterable<string>,
  edges: Map<string, readonly string[]>,
): Map<string, string[]> {
  const paths = new Map<string, string[]>();
  const queue: string[] = [];

  for (const root of roots) {
    if (paths.has(root)) continue;
    paths.set(root, [root]);
    queue.push(root);
  }

  while (queue.length) {
    const current = queue.shift()!;
    const base = paths.get(current)!;
    for (const next of edges.get(current) ?? []) {
      if (paths.has(next)) continue;
      paths.set(next, [...base, next]);
      queue.push(next);
    }
  }

  return paths;
}

/** Collapse `name@version` node ids to the name segment for `dependencyPath`. */
export function namesOnPath(ids: string[], nameOf: (id: string) => string): string[] {
  return ids.map(nameOf);
}

export function nodeId(name: string, version: string): string {
  return `${name}@${version}`;
}

export function nameFromNodeId(id: string): string {
  if (id.startsWith('@')) {
    const at = id.lastIndexOf('@');
    return at > 0 ? id.slice(0, at) : id;
  }
  const at = id.indexOf('@');
  return at === -1 ? id : id.slice(0, at);
}

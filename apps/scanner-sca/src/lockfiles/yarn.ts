import { parse as parseYaml } from 'yaml';
import { nameFromNodeId, nodeId, shortestPathsFromRoots } from './graph';
import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const yarnParser: EcosystemParser = {
  id: 'yarn',
  ecosystem: ECOSYSTEM.npm,
  group: 'javascript',
  priority: 20,
  matches: (fileName) => fileName === 'yarn.lock',
  companionFiles: ['package.json'],
  parse: (input) => {
    const directNames = directFromPackageJson(input.companions['package.json']);
    return isYarnBerry(input.content)
      ? parseYarnBerry(input.content, input.relPath, directNames)
      : parseYarnClassic(input.content, input.relPath, directNames);
  },
};

function isYarnBerry(content: string): boolean {
  return /^\s*__metadata:/m.test(content);
}

interface YarnDep {
  name: string;
  range?: string;
}

interface YarnEntry {
  name: string;
  version: string;
  deps: YarnDep[];
}

/**
 * Yarn classic (`# yarn lockfile v1`) is not YAML. Entries look like:
 *   left-pad@^1.1.1, left-pad@^1.1.3:
 *     version "1.1.3"
 *     dependencies:
 *       foo "1.0.0"
 */
export function parseYarnClassic(content: string, manifestPath: string, directNames: Set<string>) {
  const entries: YarnEntry[] = [];
  const blocks = content.split(/\n{2,}/);

  for (const block of blocks) {
    const lines = block.split('\n').filter((l) => l.trim() && !l.trimStart().startsWith('#'));
    if (!lines.length) continue;
    const header = lines[0];
    if (!header.endsWith(':') || header.startsWith(' ')) continue;
    const descriptors = splitDescriptors(header.slice(0, -1));
    const name = nameFromDescriptor(descriptors[0] ?? '');
    const versionMatch = block.match(/^\s+version\s+"([^"]+)"/m);
    if (!name || !versionMatch) continue;
    const deps: YarnDep[] = [];
    let inDeps = false;
    for (const line of lines) {
      if (/^\s+dependencies:/.test(line)) {
        inDeps = true;
        continue;
      }
      if (inDeps) {
        if (!/^\s{4}\S/.test(line)) {
          inDeps = false;
          continue;
        }
        const m = /^\s{4}(?:"([^"]+)"|(\S+))\s+"([^"]*)"/.exec(line);
        const depName = m?.[1] ?? m?.[2];
        if (depName) deps.push({ name: depName, range: m?.[3] });
      }
    }
    entries.push({ name, version: versionMatch[1], deps });
  }

  return toComponents(entries, manifestPath, directNames);
}

function parseYarnBerry(content: string, manifestPath: string, directNames: Set<string>) {
  const doc = parseYaml(content) as Record<string, unknown> | null;
  if (!doc || typeof doc !== 'object') return [];

  const entries: YarnEntry[] = [];
  for (const [key, value] of Object.entries(doc)) {
    if (key === '__metadata' || !value || typeof value !== 'object') continue;
    const entry = value as {
      version?: string;
      linkType?: string;
      dependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    };
    if (!entry.version || entry.linkType === 'soft') continue;
    const name = nameFromDescriptor(key.split(',')[0]?.trim() ?? '');
    if (!name) continue;
    entries.push({
      name,
      version: String(entry.version),
      deps: [
        ...Object.entries(entry.dependencies ?? {}).map(([depName, range]) => ({
          name: depName,
          range,
        })),
        ...Object.entries(entry.optionalDependencies ?? {}).map(([depName, range]) => ({
          name: depName,
          range,
        })),
      ],
    });
  }
  return toComponents(entries, manifestPath, directNames);
}

/**
 * Yarn lists one entry per descriptor, so the same package can lock two
 * versions. Deduping on name alone drops the second copy — keep every
 * `name@version`.
 */
function toComponents(entries: YarnEntry[], manifestPath: string, directNames: Set<string>) {
  const byId = new Map<string, YarnEntry>();
  const versionsByName = new Map<string, string[]>();
  for (const e of entries) {
    const id = nodeId(e.name, e.version);
    if (byId.has(id)) continue;
    byId.set(id, e);
    const versions = versionsByName.get(e.name) ?? [];
    versions.push(e.version);
    versionsByName.set(e.name, versions);
  }

  const edges = new Map<string, string[]>();
  for (const [id, e] of byId) {
    edges.set(
      id,
      e.deps
        .map((dep) => resolveYarnDep(dep, versionsByName))
        .filter((depId): depId is string => Boolean(depId)),
    );
  }

  const directIds = [...byId.values()]
    .filter((e) => directNames.has(e.name))
    .map((e) => nodeId(e.name, e.version));
  // No package.json → treat packages that nothing depends on as direct.
  const inferredDirect =
    directIds.length > 0
      ? directIds
      : [...edges.keys()].filter((id) => ![...edges.values()].some((deps) => deps.includes(id)));
  const paths = shortestPathsFromRoots(inferredDirect, edges);

  return [...byId.values()].map((e) => {
    const id = nodeId(e.name, e.version);
    const direct = inferredDirect.includes(id);
    return makeComponent({
      name: e.name,
      version: e.version,
      ecosystem: ECOSYSTEM.npm,
      purl: purlFor(ECOSYSTEM.npm, e.name, e.version),
      direct,
      dependencyPath: paths.get(id)?.map(nameFromNodeId) ?? (direct ? [e.name] : []),
      manifestPath,
    });
  });
}

function resolveYarnDep(dep: YarnDep, versionsByName: Map<string, string[]>): string | undefined {
  const versions = versionsByName.get(dep.name);
  if (!versions?.length) return undefined;
  const hint = exactVersionHint(dep.range);
  if (hint && versions.includes(hint)) return nodeId(dep.name, hint);
  return nodeId(dep.name, versions[0]);
}

/** `6.7.0` / `npm:6.7.0` → exact version; ranges (`^1.0.0`) cannot pick a copy. */
function exactVersionHint(range?: string): string | undefined {
  if (!range) return undefined;
  const raw = range.startsWith('npm:') ? range.slice('npm:'.length) : range;
  if (!raw || /[<>^*=~ ]/.test(raw)) return undefined;
  return raw;
}

export function directFromPackageJson(source?: string): Set<string> {
  if (!source) return new Set();
  try {
    const pkg = JSON.parse(source) as Record<string, Record<string, string> | undefined>;
    return new Set([
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
      ...Object.keys(pkg.optionalDependencies ?? {}),
    ]);
  } catch {
    return new Set();
  }
}

function splitDescriptors(header: string): string[] {
  return header
    .split(',')
    .map((s) => unquote(s.trim()))
    .filter(Boolean);
}

function nameFromDescriptor(descriptor: string): string {
  const raw = unquote(descriptor);
  // berry: "foo@npm:^1.0.0" / "@scope/foo@npm:1.0.0"
  const npmProto = raw.indexOf('@npm:');
  if (npmProto > 0) return raw.slice(0, npmProto);
  if (raw.startsWith('@')) {
    const at = raw.lastIndexOf('@');
    return at > 0 ? raw.slice(0, at) : raw;
  }
  const at = raw.indexOf('@');
  return at === -1 ? raw : raw.slice(0, at);
}

function unquote(value: string): string {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

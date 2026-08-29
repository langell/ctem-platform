import { nameFromNodeId, nodeId, shortestPathsFromRoots } from './graph';
import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const gemParser: EcosystemParser = {
  id: 'bundler',
  ecosystem: ECOSYSTEM.rubygems,
  group: 'ruby',
  priority: 10,
  matches: (fileName) => fileName === 'Gemfile.lock',
  parse: (input) => parseGemfileLock(input.content, input.relPath),
};

interface GemSpec {
  name: string;
  version: string;
  deps: string[];
}

/**
 * Gemfile.lock `specs:` is the resolved graph; `DEPENDENCIES` is the direct set.
 * GIT/PATH/GEM sections all contribute specs.
 */
export function parseGemfileLock(content: string, manifestPath: string) {
  const specs = parseSpecs(content);
  const byName = new Map(specs.map((s) => [s.name, s]));
  const directNames = parseDirectDependencies(content);

  const edges = new Map<string, string[]>();
  for (const spec of specs) {
    edges.set(
      nodeId(spec.name, spec.version),
      spec.deps.filter((d) => byName.has(d)).map((d) => nodeId(d, byName.get(d)!.version)),
    );
  }

  const directIds = specs.filter((s) => directNames.has(s.name)).map((s) => nodeId(s.name, s.version));
  const paths = shortestPathsFromRoots(directIds, edges);

  return specs.map((spec) => {
    const id = nodeId(spec.name, spec.version);
    const direct = directNames.has(spec.name);
    return makeComponent({
      name: spec.name,
      version: spec.version,
      ecosystem: ECOSYSTEM.rubygems,
      purl: purlFor(ECOSYSTEM.rubygems, spec.name, spec.version),
      direct,
      dependencyPath: paths.get(id)?.map(nameFromNodeId) ?? (direct ? [spec.name] : []),
      manifestPath,
    });
  });
}

function parseSpecs(content: string): GemSpec[] {
  const specs: GemSpec[] = [];
  let inSpecs = false;
  let current: GemSpec | null = null;

  for (const raw of content.split('\n')) {
    if (/^\s{2}specs:\s*$/.test(raw)) {
      inSpecs = true;
      current = null;
      continue;
    }
    if (inSpecs && /^\S/.test(raw)) {
      inSpecs = false;
      current = null;
    }
    if (!inSpecs) continue;

    const spec = /^\s{4}(\S+)\s+\(([^)]+)\)/.exec(raw);
    if (spec) {
      current = { name: spec[1], version: spec[2], deps: [] };
      specs.push(current);
      continue;
    }
    const dep = /^\s{6}(\S+)/.exec(raw);
    if (dep && current) current.deps.push(dep[1]);
  }
  return specs;
}

function parseDirectDependencies(content: string): Set<string> {
  const names = new Set<string>();
  const idx = content.search(/^DEPENDENCIES\s*$/m);
  if (idx === -1) return names;
  const rest = content.slice(idx).split(/\n(?=[A-Z])/).at(0) ?? '';
  for (const line of rest.split('\n').slice(1)) {
    const m = /^\s{2}(\S+)/.exec(line);
    if (m) names.add(m[1]);
  }
  return names;
}

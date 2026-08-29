import { nameFromNodeId, nodeId, shortestPathsFromRoots } from './graph';
import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const composerParser: EcosystemParser = {
  id: 'composer',
  ecosystem: ECOSYSTEM.packagist,
  group: 'php',
  priority: 10,
  matches: (fileName) => fileName === 'composer.lock',
  companionFiles: ['composer.json'],
  parse: (input) => parseComposerLock(input.content, input.relPath, input.companions['composer.json']),
};

interface ComposerPackage {
  name: string;
  version: string;
  license?: string | string[];
  require?: Record<string, string>;
}

/**
 * composer.lock `packages` / `packages-dev` are the resolved graph. Direct
 * names come from composer.json `require` / `require-dev` when present.
 * Platform packages (`php`, `ext-*`, `lib-*`) are not components.
 */
export function parseComposerLock(content: string, manifestPath: string, composerJson?: string) {
  const doc = JSON.parse(content) as {
    packages?: ComposerPackage[];
    'packages-dev'?: ComposerPackage[];
  };
  const packages = [...(doc.packages ?? []), ...(doc['packages-dev'] ?? [])].filter(
    (p) => p.name && p.version && !isPlatform(p.name),
  );

  const byName = new Map(packages.map((p) => [p.name, p]));
  const edges = new Map<string, string[]>();
  for (const pkg of packages) {
    const deps = Object.keys(pkg.require ?? {}).filter((n) => byName.has(n));
    edges.set(
      nodeId(pkg.name, pkg.version),
      deps.map((n) => nodeId(n, byName.get(n)!.version)),
    );
  }

  const declared = directFromComposerJson(composerJson);
  const directIds =
    declared.size > 0
      ? packages.filter((p) => declared.has(p.name)).map((p) => nodeId(p.name, p.version))
      : [...edges.keys()].filter((id) => ![...edges.values()].some((deps) => deps.includes(id)));

  const paths = shortestPathsFromRoots(directIds, edges);

  return packages.map((pkg) => {
    const id = nodeId(pkg.name, pkg.version);
    const direct = directIds.includes(id);
    const licenses = Array.isArray(pkg.license) ? pkg.license : pkg.license ? [pkg.license] : [];
    return makeComponent({
      name: pkg.name,
      version: normalizeComposerVersion(pkg.version),
      ecosystem: ECOSYSTEM.packagist,
      purl: purlFor(ECOSYSTEM.packagist, pkg.name, normalizeComposerVersion(pkg.version)),
      direct,
      dependencyPath: paths.get(id)?.map(nameFromNodeId) ?? (direct ? [pkg.name] : []),
      manifestPath,
      licenses,
    });
  });
}

function directFromComposerJson(source?: string): Set<string> {
  if (!source) return new Set();
  try {
    const doc = JSON.parse(source) as {
      require?: Record<string, string>;
      'require-dev'?: Record<string, string>;
    };
    return new Set(
      [...Object.keys(doc.require ?? {}), ...Object.keys(doc['require-dev'] ?? {})].filter(
        (n) => !isPlatform(n),
      ),
    );
  } catch {
    return new Set();
  }
}

function isPlatform(name: string): boolean {
  return (
    name === 'php' ||
    name === 'hhvm' ||
    name === 'composer-plugin-api' ||
    name === 'composer-runtime-api' ||
    name.startsWith('ext-') ||
    name.startsWith('lib-')
  );
}

function normalizeComposerVersion(version: string): string {
  return version.replace(/^v(?=\d)/, '');
}

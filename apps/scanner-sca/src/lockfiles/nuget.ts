import { nameFromNodeId, nodeId, shortestPathsFromRoots } from './graph';
import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const nugetLockParser: EcosystemParser = {
  id: 'nuget-lock',
  ecosystem: ECOSYSTEM.nuget,
  group: 'nuget',
  priority: 20,
  matches: (fileName) => fileName === 'packages.lock.json',
  parse: (input) => parsePackagesLock(input.content, input.relPath),
};

export const csprojParser: EcosystemParser = {
  id: 'csproj',
  ecosystem: ECOSYSTEM.nuget,
  group: 'nuget',
  priority: 10,
  matches: (fileName) => fileName.endsWith('.csproj'),
  parse: (input) => parseCsproj(input.content, input.relPath),
};

interface NugetLockDep {
  type?: string;
  resolved?: string;
  dependencies?: Record<string, string>;
}

/**
 * packages.lock.json is the NuGet lockfile and carries type=Direct|Transitive
 * plus a per-package dependency map. The same package can appear under several
 * TFMs; we keep one name@version.
 */
export function parsePackagesLock(content: string, manifestPath: string) {
  const doc = JSON.parse(content) as {
    dependencies?: Record<string, Record<string, NugetLockDep>>;
  };
  const byName = new Map<string, { version: string; direct: boolean; deps: string[] }>();

  for (const tfm of Object.values(doc.dependencies ?? {})) {
    for (const [name, info] of Object.entries(tfm)) {
      if (!info.resolved || info.type === 'Project') continue;
      const existing = byName.get(name);
      const direct = info.type === 'Direct';
      if (!existing) {
        byName.set(name, {
          version: info.resolved,
          direct,
          deps: Object.keys(info.dependencies ?? {}),
        });
      } else if (direct) {
        existing.direct = true;
      }
    }
  }

  const edges = new Map<string, string[]>();
  for (const [name, info] of byName) {
    edges.set(
      nodeId(name, info.version),
      info.deps.filter((d) => byName.has(d)).map((d) => nodeId(d, byName.get(d)!.version)),
    );
  }
  const directIds = [...byName.entries()]
    .filter(([, info]) => info.direct)
    .map(([name, info]) => nodeId(name, info.version));
  const paths = shortestPathsFromRoots(directIds, edges);

  return [...byName.entries()].map(([name, info]) => {
    const id = nodeId(name, info.version);
    return makeComponent({
      name,
      version: info.version,
      ecosystem: ECOSYSTEM.nuget,
      purl: purlFor(ECOSYSTEM.nuget, name, info.version),
      direct: info.direct,
      dependencyPath: paths.get(id)?.map(nameFromNodeId) ?? (info.direct ? [name] : []),
      manifestPath,
    });
  });
}

/**
 * *.csproj `PackageReference` items are direct, pinned dependencies only.
 * Ranges (`1.*`, `[1.0,2.0)`) are skipped. There is no transitive graph
 * without packages.lock.json.
 */
export function parseCsproj(content: string, manifestPath: string) {
  const xml = content.replace(/<!--[\s\S]*?-->/g, '');
  const seen = new Map<string, string>();

  for (const { attrs, inner } of packageReferences(xml)) {
    const name = attr(attrs, 'Include') ?? attr(attrs, 'Update');
    const version = attr(attrs, 'Version') ?? tag(inner, 'Version');
    if (!name || !version || !isPinnedNuget(version)) continue;
    if (!seen.has(name)) seen.set(name, version);
  }

  return [...seen.entries()].map(([name, version]) =>
    makeComponent({
      name,
      version,
      ecosystem: ECOSYSTEM.nuget,
      purl: purlFor(ECOSYSTEM.nuget, name, version),
      direct: true,
      dependencyPath: [name],
      manifestPath,
    }),
  );
}

function* packageReferences(xml: string): Generator<{ attrs: string; inner: string }> {
  const start = /<PackageReference\b/gi;
  let match: RegExpExecArray | null;
  while ((match = start.exec(xml))) {
    const rest = xml.slice(match.index + match[0].length);
    const selfClose = /^([^>]*?)\/>/.exec(rest);
    if (selfClose) {
      yield { attrs: selfClose[1], inner: '' };
      continue;
    }
    const paired = /^([^>]*)>([\s\S]*?)<\/PackageReference>/i.exec(rest);
    if (paired) yield { attrs: paired[1], inner: paired[2] };
  }
}

function attr(attrs: string, name: string): string | null {
  const m = new RegExp(`${name}\\s*=\\s*"([^"]+)"`, 'i').exec(attrs);
  return m?.[1] ?? null;
}

function tag(inner: string, name: string): string | null {
  const m = new RegExp(`<${name}>([^<]+)</${name}>`, 'i').exec(inner);
  return m?.[1].trim() ?? null;
}

function isPinnedNuget(version: string): boolean {
  return !/[[(,*\]]/.test(version);
}

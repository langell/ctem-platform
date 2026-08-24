import { Injectable } from '@nestjs/common';
import { ArtifactStore } from '@ctem/storage';

export interface ResolvedComponent {
  purl: string;
  name: string;
  version: string;
  ecosystem: string;
  direct: boolean;
  dependencyPath: string[];
  licenses: string[];
  manifestPath?: string;
}

interface CycloneDxComponent {
  'bom-ref'?: string;
  purl?: string;
  name: string;
  version: string;
  licenses?: Array<{ license?: { id?: string; name?: string } }>;
}

interface CycloneDxDocument {
  bomFormat?: string;
  metadata?: { component?: { 'bom-ref'?: string } };
  components?: CycloneDxComponent[];
  dependencies?: Array<{ ref: string; dependsOn?: string[] }>;
}

/**
 * CycloneDX first — it is what most CI toolchains emit and it carries the
 * dependency graph, which is what lets us distinguish "you depend on this" from
 * "something you depend on depends on this".
 */
@Injectable()
export class SbomParser {
  constructor(private readonly artifacts: ArtifactStore) {}

  async fromArtifact(key: string): Promise<ResolvedComponent[]> {
    const doc = await this.artifacts.getJson<CycloneDxDocument>(key);
    return this.parseCycloneDx(doc);
  }

  parseCycloneDx(doc: CycloneDxDocument): ResolvedComponent[] {
    const rootRef = doc.metadata?.component?.['bom-ref'];
    const directRefs = new Set(
      doc.dependencies?.find((d) => d.ref === rootRef)?.dependsOn ?? [],
    );
    const paths = shortestPaths(rootRef, doc.dependencies ?? []);
    const nameByRef = new Map(
      (doc.components ?? []).map((c) => [c['bom-ref'] ?? c.purl ?? `${c.name}@${c.version}`, c.name]),
    );

    return (doc.components ?? []).map((c) => {
      const ref = c['bom-ref'] ?? c.purl ?? `${c.name}@${c.version}`;
      return {
        purl: c.purl ?? `pkg:generic/${c.name}@${c.version}`,
        name: c.name,
        version: c.version,
        ecosystem: this.ecosystemFromPurl(c.purl),
        direct: directRefs.has(ref),
        // The "why is this even here" answer: names from a direct dependency
        // down to this component, e.g. ['express', 'body-parser', 'qs'].
        dependencyPath: (paths.get(ref) ?? []).map((r) => nameByRef.get(r) ?? r),
        licenses:
          c.licenses?.map((l) => l.license?.id ?? l.license?.name ?? 'unknown').filter(Boolean) ?? [],
      };
    });
  }

  private ecosystemFromPurl(purl?: string): string {
    if (!purl) return 'unknown';
    const match = /^pkg:([^/]+)\//.exec(purl);
    const type = match?.[1] ?? 'unknown';
    // OSV uses its own ecosystem names; normalize once here rather than at every call site.
    const map: Record<string, string> = {
      npm: 'npm',
      pypi: 'PyPI',
      maven: 'Maven',
      golang: 'Go',
      cargo: 'crates.io',
      gem: 'RubyGems',
      nuget: 'NuGet',
      composer: 'Packagist',
      deb: 'Debian',
      apk: 'Alpine',
      rpm: 'Red Hat',
    };
    return map[type] ?? type;
  }
}

/**
 * BFS from the root over the CycloneDX dependency graph. Returns, per ref, the
 * shortest chain of refs from a direct dependency down to that ref inclusive
 * (the root itself is omitted — it is the application being scanned). BFS
 * guarantees the shortest explanation, and the visited set makes cycles safe.
 */
function shortestPaths(
  rootRef: string | undefined,
  dependencies: Array<{ ref: string; dependsOn?: string[] }>,
): Map<string, string[]> {
  const paths = new Map<string, string[]>();
  if (!rootRef) return paths;

  const edges = new Map(dependencies.map((d) => [d.ref, d.dependsOn ?? []]));
  const queue: string[] = [rootRef];
  paths.set(rootRef, []);

  while (queue.length) {
    const current = queue.shift()!;
    const basePath = paths.get(current)!;
    for (const next of edges.get(current) ?? []) {
      if (paths.has(next)) continue;
      paths.set(next, [...basePath, next]);
      queue.push(next);
    }
  }

  paths.delete(rootRef);
  return paths;
}

import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const golangParser: EcosystemParser = {
  id: 'golang',
  ecosystem: ECOSYSTEM.go,
  group: 'golang',
  priority: 10,
  matches: (fileName) => fileName === 'go.sum' || fileName === 'go.mod',
  companionFiles: ['go.mod', 'go.sum'],
  parse: (input) =>
    parseGoModules(
      input.companions['go.mod'] ?? (input.relPath.endsWith('go.mod') ? input.content : ''),
      input.companions['go.sum'] ?? (input.relPath.endsWith('go.sum') ? input.content : ''),
      input.relPath.endsWith('go.sum') ? input.relPath : input.relPath.replace(/go\.mod$/, 'go.sum'),
    ),
};

/**
 * go.mod carries exact versions plus `// indirect`. go.sum is a checksum list —
 * it has no graph. Combined:
 *   - versions come from both (union of every name@version; go.sum can
 *     checksum more than one version of a module)
 *   - direct vs transitive comes from go.mod
 *   - dependencyPath is `[module]` for direct modules and empty otherwise
 *
 * Limitation: there is no lockfile graph, so transitive paths cannot be
 * reconstructed without invoking `go mod graph`.
 */
export function parseGoModules(goMod: string, goSum: string, manifestPath: string) {
  const fromMod = parseGoMod(goMod);
  const fromSum = parseGoSum(goSum);

  // go.sum lists every checksummed version (two lines per version). Keep each
  // name@version — first-version-wins would drop a second locked copy.
  const byId = new Map<string, { name: string; version: string; direct: boolean }>();
  for (const { name, version } of fromSum) {
    byId.set(`${name}@${version}`, { name, version, direct: false });
  }
  for (const req of fromMod.requires) {
    byId.set(`${req.name}@${req.version}`, { name: req.name, version: req.version, direct: req.direct });
  }
  for (const rep of fromMod.replaces) {
    if (rep.newName && rep.newVersion) {
      for (const [id, info] of byId) {
        if (info.name === rep.oldName) byId.delete(id);
      }
      byId.set(`${rep.newName}@${rep.newVersion}`, {
        name: rep.newName,
        version: rep.newVersion,
        direct: fromMod.requires.find((r) => r.name === rep.oldName)?.direct ?? false,
      });
    }
  }

  const path = manifestPath.endsWith('go.mod') ? manifestPath.replace(/go\.mod$/, 'go.sum') || 'go.sum' : manifestPath;
  return [...byId.values()].map((info) =>
    makeComponent({
      name: info.name,
      version: info.version,
      ecosystem: ECOSYSTEM.go,
      purl: purlFor(ECOSYSTEM.go, info.name, info.version),
      direct: info.direct,
      dependencyPath: info.direct ? [info.name] : [],
      manifestPath: path,
    }),
  );
}

export function parseGoMod(content: string): {
  requires: Array<{ name: string; version: string; direct: boolean }>;
  replaces: Array<{ oldName: string; newName?: string; newVersion?: string }>;
} {
  const requires: Array<{ name: string; version: string; direct: boolean }> = [];
  const replaces: Array<{ oldName: string; newName?: string; newVersion?: string }> = [];
  if (!content) return { requires, replaces };

  const lines = content.split('\n');
  let block: 'require' | 'replace' | null = null;

  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    if (line === ')') {
      block = null;
      continue;
    }
    if (line.startsWith('require (')) {
      block = 'require';
      continue;
    }
    if (line.startsWith('replace (')) {
      block = 'replace';
      continue;
    }
    if (line.startsWith('require ')) {
      const req = parseRequireLine(line.slice('require '.length), raw);
      if (req) requires.push(req);
      continue;
    }
    if (line.startsWith('replace ')) {
      const rep = parseReplaceLine(line.slice('replace '.length));
      if (rep) replaces.push(rep);
      continue;
    }
    if (block === 'require') {
      const req = parseRequireLine(line, raw);
      if (req) requires.push(req);
    } else if (block === 'replace') {
      const rep = parseReplaceLine(line);
      if (rep) replaces.push(rep);
    }
  }
  return { requires, replaces };
}

export function parseGoSum(content: string): Array<{ name: string; version: string }> {
  const out: Array<{ name: string; version: string }> = [];
  const seen = new Set<string>();
  if (!content) return out;
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 2) continue;
    const name = parts[0];
    let version = parts[1];
    if (version.endsWith('/go.mod')) version = version.slice(0, -'/go.mod'.length);
    const id = `${name}@${version}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ name, version });
  }
  return out;
}

function parseRequireLine(
  line: string,
  original: string,
): { name: string; version: string; direct: boolean } | null {
  const parts = line.split(/\s+/);
  if (parts.length < 2) return null;
  const [name, version] = parts;
  if (!name || !version || name === 'module' || version.startsWith('(')) return null;
  const direct = !/\/\/\s*indirect\b/.test(original);
  return { name, version, direct };
}

function parseReplaceLine(line: string): { oldName: string; newName?: string; newVersion?: string } | null {
  const m = line.match(/^(\S+)(?:\s+\S+)?\s*=>\s*(\S+)(?:\s+(\S+))?/);
  if (!m) return null;
  const newTarget = m[2];
  const newVersion = m[3];
  // Path replaces (./foo, ../foo, /abs) have no module identity we can match.
  if (newTarget.startsWith('.') || newTarget.startsWith('/')) {
    return { oldName: m[1] };
  }
  return { oldName: m[1], newName: newTarget, newVersion };
}


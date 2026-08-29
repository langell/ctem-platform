import { purlFor } from './purl';
import { ECOSYSTEM, makeComponent, type EcosystemParser } from './types';

export const pipParser: EcosystemParser = {
  id: 'pip',
  ecosystem: ECOSYSTEM.pypi,
  group: 'python',
  priority: 10,
  matches: (fileName) => fileName === 'requirements.txt',
  parse: (input) => parseRequirementsTxt(input.content, input.relPath),
};

/**
 * requirements.txt is only a lockfile when every installable line is pinned
 * (`name==version` / `name===version`). Range operators, VCS, and editables
 * are skipped — those are guesses, not resolved versions.
 *
 * Limitation: there is no graph, so every pinned package is marked direct
 * with `dependencyPath = [name]`.
 */
export function parseRequirementsTxt(content: string, manifestPath: string) {
  const seen = new Map<string, string>();
  for (const raw of content.split('\n')) {
    const line = raw.replace(/\\$/, '').split('#')[0].trim();
    if (!line || line.startsWith('-') || line.startsWith('--')) continue;
    const pinned = parsePinnedRequirement(line);
    if (!pinned) continue;
    if (!seen.has(pinned.name)) seen.set(pinned.name, pinned.version);
  }

  return [...seen.entries()].map(([name, version]) =>
    makeComponent({
      name,
      version,
      ecosystem: ECOSYSTEM.pypi,
      purl: purlFor(ECOSYSTEM.pypi, name, version),
      direct: true,
      dependencyPath: [name],
      manifestPath,
    }),
  );
}

export function parsePinnedRequirement(line: string): { name: string; version: string } | null {
  const stripped = line.replace(/;.*$/, '').replace(/\s+--hash=.*$/, '').trim();
  const m = /^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*===?\s*([^\s\\]+)$/.exec(stripped);
  if (!m) return null;
  return { name: m[1], version: m[2] };
}

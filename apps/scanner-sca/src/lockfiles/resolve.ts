import { readFile } from 'node:fs/promises';
import { rootLogger } from '@ctem/observability';
import { cargoParser } from './cargo';
import { composerParser } from './composer';
import { gemParser } from './gem';
import { golangParser } from './golang';
import { gradleParser, pomParser } from './maven';
import { npmParser } from './npm';
import { csprojParser, nugetLockParser } from './nuget';
import { pipParser } from './pip';
import { pnpmParser } from './pnpm';
import { poetryParser } from './poetry';
import type { EcosystemParser, ResolvedComponent } from './types';
import { listRepoFiles, posixDir } from './walk';
import { yarnParser } from './yarn';

const log = rootLogger.child({ component: 'lockfile-resolve' });

/**
 * Lockfile-first discovery. Parsers that share a group compete inside one
 * directory so `package.json` / `pom.xml` / `*.csproj` never override a lockfile.
 */
export const PARSERS: EcosystemParser[] = [
  pnpmParser,
  yarnParser,
  npmParser,
  cargoParser,
  golangParser,
  poetryParser,
  pipParser,
  gemParser,
  gradleParser,
  pomParser,
  composerParser,
  nugetLockParser,
  csprojParser,
];

export async function resolveLockfiles(repoRoot: string): Promise<ResolvedComponent[]> {
  const files = await listRepoFiles(repoRoot);
  if (!files.length) return [];

  const byDir = new Map<string, typeof files>();
  for (const file of files) {
    const dir = posixDir(file.relPath);
    const list = byDir.get(dir) ?? [];
    list.push(file);
    byDir.set(dir, list);
  }

  const contents = new Map<string, string>();
  const read = async (relPath: string, absPath: string): Promise<string> => {
    const cached = contents.get(relPath);
    if (cached !== undefined) return cached;
    const text = await readFile(absPath, 'utf8');
    contents.set(relPath, text);
    return text;
  };

  const selected: Array<{ parser: EcosystemParser; file: (typeof files)[number]; dirFiles: typeof files }> = [];

  for (const dirFiles of byDir.values()) {
    const winners = new Map<string, { parser: EcosystemParser; file: (typeof files)[number] }>();
    for (const file of dirFiles) {
      for (const parser of PARSERS) {
        if (!parser.matches(file.fileName)) continue;
        const current = winners.get(parser.group);
        if (!current || parser.priority > current.parser.priority) {
          winners.set(parser.group, { parser, file });
        }
      }
    }
    for (const { parser, file } of winners.values()) {
      selected.push({ parser, file, dirFiles });
    }
  }

  const collected: ResolvedComponent[] = [];
  for (const { parser, file, dirFiles } of selected) {
    try {
      const companions: Record<string, string> = {};
      for (const sibling of dirFiles) {
        companions[sibling.fileName] = await read(sibling.relPath, sibling.absPath);
      }
      const parsed = parser.parse({
        relPath: file.relPath,
        content: companions[file.fileName] ?? (await read(file.relPath, file.absPath)),
        companions,
      });
      collected.push(...parsed);
    } catch (err) {
      log.warn({ err, parser: parser.id, file: file.relPath }, 'lockfile parse failed — skipping');
    }
  }

  return dedupeComponents(collected);
}

/** Same package from several lockfiles: prefer a direct hit, then a shorter path. */
export function dedupeComponents(components: ResolvedComponent[]): ResolvedComponent[] {
  const byKey = new Map<string, ResolvedComponent>();
  for (const component of components) {
    const key = `${component.ecosystem}:${component.name}@${component.version}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, component);
      continue;
    }
    if (component.direct && !existing.direct) {
      byKey.set(key, component);
      continue;
    }
    if (
      component.direct === existing.direct &&
      component.dependencyPath.length > 0 &&
      (existing.dependencyPath.length === 0 ||
        component.dependencyPath.length < existing.dependencyPath.length)
    ) {
      byKey.set(key, component);
    }
  }
  return [...byKey.values()];
}

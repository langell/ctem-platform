import { parseCycloneDx, type CycloneDxDocument } from '../sbom.parser';
import { ECOSYSTEM, type EcosystemParser } from './types';

/**
 * Committed CycloneDX JSON discovered during the lockfile walk.
 *
 * Exact names (one BOM per directory; highest `fileRank` wins, then
 * lexicographic): `bom.json` > `cyclonedx.json` > first `*.cdx.json`.
 *
 * Group `java` at priority 40 so this beats `gradle.lockfile` (20) and
 * `pom.xml` (10) in the same directory — the Java preference chain is
 * exclusive per directory, like Python. A BOM next to `package-lock.json`
 * still sits alongside that winner (different groups). Own group `sbom`
 * was not used: it would emit duplicate Maven coordinates from BOM +
 * gradle/pom in the same folder.
 */
export const cyclonedxParser: EcosystemParser = {
  id: 'cyclonedx',
  ecosystem: ECOSYSTEM.maven,
  group: 'java',
  priority: 40,
  matches: isCycloneDxFileName,
  fileRank: cycloneDxFileRank,
  parse: (input) => parseCycloneDxLockfile(input.content, input.relPath),
};

export function isCycloneDxFileName(fileName: string): boolean {
  return fileName === 'bom.json' || fileName === 'cyclonedx.json' || fileName.endsWith('.cdx.json');
}

/** `bom.json` (3) > `cyclonedx.json` (2) > `*.cdx.json` (1). */
export function cycloneDxFileRank(fileName: string): number {
  if (fileName === 'bom.json') return 3;
  if (fileName === 'cyclonedx.json') return 2;
  if (fileName.endsWith('.cdx.json')) return 1;
  return 0;
}

/**
 * JSON.parse + CycloneDX graph. Malformed / non-CycloneDX documents throw so
 * resolve can skip-with-warn and fail closed when this was the only winner.
 */
export function parseCycloneDxLockfile(content: string, manifestPath: string) {
  let doc: unknown;
  try {
    doc = JSON.parse(content);
  } catch {
    throw new Error(`${manifestPath} is not valid JSON`);
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error(`${manifestPath} is not a CycloneDX JSON object`);
  }
  const bom = doc as CycloneDxDocument;
  if (bom.bomFormat !== 'CycloneDX') {
    throw new Error(`${manifestPath} is not CycloneDX JSON (bomFormat=${String(bom.bomFormat)})`);
  }
  return parseCycloneDx(bom).map((component) => ({ ...component, manifestPath }));
}

import type { ResolvedComponent } from '../sbom.parser';

export type { ResolvedComponent };

/** OSV ecosystem names — must match `SbomParser.ecosystemFromPurl`. */
export const ECOSYSTEM = {
  npm: 'npm',
  pypi: 'PyPI',
  cargo: 'crates.io',
  go: 'Go',
  rubygems: 'RubyGems',
  maven: 'Maven',
  nuget: 'NuGet',
  packagist: 'Packagist',
} as const;

export interface LockfileInput {
  /** Path relative to the repo root (forward slashes), stored as `manifestPath`. */
  relPath: string;
  content: string;
  /** Other files in the same directory, keyed by basename. */
  companions: Record<string, string>;
}

/**
 * One lockfile format. Parsers that share a `group` compete inside a directory:
 * the highest `priority` match wins so a range-y manifest never overrides a lockfile.
 */
export interface EcosystemParser {
  id: string;
  ecosystem: string;
  group: string;
  priority: number;
  matches: (fileName: string) => boolean;
  /** Basenames we will read besides the lockfile itself. Never slurp the whole directory. */
  companionFiles?: string[];
  parse: (input: LockfileInput) => ResolvedComponent[];
}

export function makeComponent(partial: {
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
  direct: boolean;
  dependencyPath: string[];
  manifestPath: string;
  licenses?: string[];
}): ResolvedComponent {
  return {
    licenses: [],
    ...partial,
  };
}

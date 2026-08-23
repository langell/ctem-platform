/**
 * Evaluates whether a concrete version falls inside an OSV advisory's
 * `affected` ranges. Pure functions so the logic is trivially testable — it is
 * the correctness-critical heart of local matching.
 *
 * Comparison is semver-shaped but tolerant: numeric dot-segments compared
 * numerically, a release outranks its own prereleases, unknown formats fall
 * back to segment-wise string comparison. OSV's enumerated `versions` list is
 * preferred whenever present because membership needs no comparison at all.
 */

export interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  versions?: string[];
  ranges?: Array<{
    type?: string;
    events?: Array<{ introduced?: string; fixed?: string; last_affected?: string; limit?: string }>;
  }>;
}

export function versionAffected(
  version: string,
  affected: OsvAffected[] | undefined,
  pkg?: { name?: string; ecosystem?: string },
): boolean {
  for (const entry of affected ?? []) {
    if (pkg?.name && entry.package?.name && entry.package.name !== pkg.name) continue;
    if (pkg?.ecosystem && entry.package?.ecosystem && entry.package.ecosystem !== pkg.ecosystem) {
      continue;
    }

    if (entry.versions?.length) {
      if (entry.versions.includes(version) || entry.versions.includes(`v${version}`)) return true;
      continue; // an explicit list is authoritative for this entry
    }

    for (const range of entry.ranges ?? []) {
      // GIT ranges compare commit hashes, which we cannot order here.
      if (range.type === 'GIT') continue;
      if (inRange(version, range.events ?? [])) return true;
    }
  }
  return false;
}

/** Walks the (sorted, per OSV spec) event list pairing introduced/fixed intervals. */
function inRange(
  version: string,
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string; limit?: string }>,
): boolean {
  let openedAt: string | null = null;

  for (const event of events) {
    if (event.introduced !== undefined) {
      openedAt = event.introduced;
    } else if (event.fixed !== undefined && openedAt !== null) {
      if (gte(version, openedAt) && compareVersions(version, event.fixed) < 0) return true;
      openedAt = null;
    } else if (event.last_affected !== undefined && openedAt !== null) {
      if (gte(version, openedAt) && compareVersions(version, event.last_affected) <= 0) return true;
      openedAt = null;
    }
  }

  // A trailing `introduced` with no closing event means "affected ever since".
  return openedAt !== null && gte(version, openedAt);
}

function gte(version: string, introduced: string): boolean {
  return introduced === '0' || compareVersions(version, introduced) >= 0;
}

export function compareVersions(a: string, b: string): number {
  const [mainA, preA] = splitPrerelease(normalize(a));
  const [mainB, preB] = splitPrerelease(normalize(b));

  const main = compareDotted(mainA, mainB);
  if (main !== 0) return main;

  // Same main version: a release outranks any of its prereleases.
  if (preA === null && preB === null) return 0;
  if (preA === null) return 1;
  if (preB === null) return -1;
  return compareDotted(preA, preB);
}

function normalize(v: string): string {
  const stripped = v.trim().replace(/^v/i, '');
  const plus = stripped.indexOf('+'); // build metadata never orders
  return plus === -1 ? stripped : stripped.slice(0, plus);
}

function splitPrerelease(v: string): [string, string | null] {
  const dash = v.indexOf('-');
  return dash === -1 ? [v, null] : [v.slice(0, dash), v.slice(dash + 1)];
}

function compareDotted(a: string, b: string): number {
  const segsA = a.split('.');
  const segsB = b.split('.');
  const len = Math.max(segsA.length, segsB.length);

  for (let i = 0; i < len; i++) {
    const sa = segsA[i];
    const sb = segsB[i];
    // Shorter runs of segments sort first: 1.2 < 1.2.1, alpha < alpha.1.
    if (sa === undefined) return -1;
    if (sb === undefined) return 1;

    const na = /^\d+$/.test(sa) ? Number(sa) : null;
    const nb = /^\d+$/.test(sb) ? Number(sb) : null;
    if (na !== null && nb !== null) {
      if (na !== nb) return na < nb ? -1 : 1;
    } else if (na !== null) {
      return -1; // numeric identifiers sort before alphanumeric (semver rule)
    } else if (nb !== null) {
      return 1;
    } else if (sa !== sb) {
      return sa < sb ? -1 : 1;
    }
  }
  return 0;
}

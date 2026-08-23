import { describe, expect, it } from 'vitest';
import {
  chunk,
  computeEpssUpdates,
  computeKevUpdates,
  resolveCve,
} from './enrichment.logic';

const row = (over: Partial<Parameters<typeof computeKevUpdates>[0][number]> = {}) => ({
  id: 'GHSA-xxxx',
  aliases: ['CVE-2024-1111'],
  kev: false,
  kevDueDate: null,
  epssScore: null,
  ...over,
});

describe('resolveCve', () => {
  it('prefers a CVE id, falls back to a CVE alias, else null', () => {
    expect(resolveCve({ id: 'CVE-2024-2222', aliases: [] })).toBe('CVE-2024-2222');
    expect(resolveCve({ id: 'GHSA-x', aliases: ['OSV-1', 'CVE-2024-1111'] })).toBe('CVE-2024-1111');
    expect(resolveCve({ id: 'OSV-1', aliases: [] })).toBeNull();
  });
});

describe('computeKevUpdates', () => {
  const due = new Date('2026-09-01');

  it('flags newly-listed advisories with their due date', () => {
    const updates = computeKevUpdates([row()], new Map([['CVE-2024-1111', { dueDate: due }]]));
    expect(updates).toEqual([
      { id: 'GHSA-xxxx', cve: 'CVE-2024-1111', kev: true, kevDueDate: due },
    ]);
  });

  it('clears advisories that dropped off the catalog', () => {
    const updates = computeKevUpdates([row({ kev: true, kevDueDate: due })], new Map());
    expect(updates).toEqual([
      { id: 'GHSA-xxxx', cve: 'CVE-2024-1111', kev: false, kevDueDate: null },
    ]);
  });

  it('is silent when nothing changed', () => {
    const listed = new Map([['CVE-2024-1111', { dueDate: due }]]);
    expect(computeKevUpdates([row({ kev: true, kevDueDate: due })], listed)).toEqual([]);
    expect(computeKevUpdates([row()], new Map())).toEqual([]);
  });

  it('ignores advisories with no CVE identity', () => {
    const noCve = row({ id: 'OSV-9', aliases: [] });
    expect(computeKevUpdates([noCve], new Map([['CVE-x', { dueDate: null }]]))).toEqual([]);
  });
});

describe('computeEpssUpdates', () => {
  const scores = new Map([['CVE-2024-1111', { epss: 0.42, percentile: 0.97 }]]);

  it('sets a score where none existed', () => {
    expect(computeEpssUpdates([row()], scores)).toEqual([
      { id: 'GHSA-xxxx', cve: 'CVE-2024-1111', epssScore: 0.42, epssPercentile: 0.97 },
    ]);
  });

  it('updates only on movement beyond the noise threshold', () => {
    expect(computeEpssUpdates([row({ epssScore: 0.4195 })], scores)).toHaveLength(0);
    expect(computeEpssUpdates([row({ epssScore: 0.3 })], scores)).toHaveLength(1);
  });

  it('leaves rows alone when EPSS has no data for them', () => {
    expect(computeEpssUpdates([row()], new Map())).toEqual([]);
  });
});

describe('chunk', () => {
  it('splits into fixed-size batches with a short tail', () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
    expect(chunk([], 10)).toEqual([]);
  });
});

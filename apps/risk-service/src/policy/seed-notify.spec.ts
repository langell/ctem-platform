import { describe, expect, it } from 'vitest';
import { matchesSeedKevOrCritical } from './seed-notify';

describe('matchesSeedKevOrCritical', () => {
  it('fires for a KEV finding at any severity', () => {
    expect(matchesSeedKevOrCritical({ kev: true, severity: 'medium' })).toBe(true);
    expect(matchesSeedKevOrCritical({ kev: true, severity: 'low' })).toBe(true);
  });

  it('fires for a critical finding that is not on KEV', () => {
    expect(matchesSeedKevOrCritical({ kev: false, severity: 'critical' })).toBe(true);
  });

  it('does not fire for high/medium/low without KEV', () => {
    expect(matchesSeedKevOrCritical({ kev: false, severity: 'high' })).toBe(false);
    expect(matchesSeedKevOrCritical({ kev: false, severity: 'medium' })).toBe(false);
    expect(matchesSeedKevOrCritical({ kev: false, severity: 'low' })).toBe(false);
  });
});

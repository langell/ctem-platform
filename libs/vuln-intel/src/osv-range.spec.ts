import { describe, expect, it } from 'vitest';
import { compareVersions, versionAffected } from './osv-range';

describe('compareVersions', () => {
  it.each([
    ['1.2.3', '1.2.3', 0],
    ['1.2.3', '1.2.4', -1],
    ['1.10.0', '1.9.9', 1],
    ['1.2', '1.2.1', -1],
    ['v2.0.0', '2.0.0', 0],
    ['2.0.0+build5', '2.0.0', 0],
    ['1.0.0-alpha', '1.0.0', -1],
    ['1.0.0-alpha', '1.0.0-beta', -1],
    ['1.0.0-alpha.1', '1.0.0-alpha', 1],
    ['1.0.0-1', '1.0.0-alpha', -1], // numeric prerelease sorts before alphanumeric
  ])('%s vs %s → %i', (a, b, expected) => {
    expect(Math.sign(compareVersions(a, b))).toBe(expected);
  });
});

describe('versionAffected', () => {
  const semverRange = (events: Array<Record<string, string>>) => [
    { package: { name: 'express', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events }] },
  ];

  it('matches inside an introduced/fixed interval, exclusive of the fix', () => {
    const affected = semverRange([{ introduced: '4.0.0' }, { fixed: '4.17.3' }]);
    expect(versionAffected('4.17.1', affected)).toBe(true);
    expect(versionAffected('4.17.3', affected)).toBe(false);
    expect(versionAffected('3.9.9', affected)).toBe(false);
  });

  it('treats introduced "0" as since-forever and last_affected as inclusive', () => {
    const affected = semverRange([{ introduced: '0' }, { last_affected: '2.1.0' }]);
    expect(versionAffected('0.0.1', affected)).toBe(true);
    expect(versionAffected('2.1.0', affected)).toBe(true);
    expect(versionAffected('2.1.1', affected)).toBe(false);
  });

  it('treats a trailing introduced with no fix as open-ended', () => {
    const affected = semverRange([{ introduced: '1.0.0' }]);
    expect(versionAffected('99.0.0', affected)).toBe(true);
    expect(versionAffected('0.9.0', affected)).toBe(false);
  });

  it('prefers the enumerated versions list when present', () => {
    const affected = [
      {
        package: { name: 'qs', ecosystem: 'npm' },
        versions: ['6.7.0', '6.7.1'],
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
      },
    ];
    expect(versionAffected('6.7.0', affected)).toBe(true);
    expect(versionAffected('6.7.2', affected)).toBe(false);
  });

  it('filters entries by package when identifiers are provided', () => {
    const affected = semverRange([{ introduced: '0' }]);
    expect(versionAffected('1.0.0', affected, { name: 'express', ecosystem: 'npm' })).toBe(true);
    expect(versionAffected('1.0.0', affected, { name: 'koa', ecosystem: 'npm' })).toBe(false);
    expect(versionAffected('1.0.0', affected, { name: 'express', ecosystem: 'PyPI' })).toBe(false);
  });

  it('ignores GIT ranges rather than guessing at hash ordering', () => {
    const affected = [
      { ranges: [{ type: 'GIT', events: [{ introduced: '0' }, { fixed: 'abc123' }] }] },
    ];
    expect(versionAffected('1.0.0', affected)).toBe(false);
  });

  it('handles multiple intervals in one range', () => {
    const affected = semverRange([
      { introduced: '1.0.0' },
      { fixed: '1.2.0' },
      { introduced: '2.0.0' },
      { fixed: '2.3.0' },
    ]);
    expect(versionAffected('1.1.0', affected)).toBe(true);
    expect(versionAffected('1.5.0', affected)).toBe(false);
    expect(versionAffected('2.2.9', affected)).toBe(true);
    expect(versionAffected('2.3.0', affected)).toBe(false);
  });
});

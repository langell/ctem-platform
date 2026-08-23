import { afterEach, describe, expect, it, vi } from 'vitest';
import { VulnMatcher } from './vuln.matcher';
import type { ResolvedComponent } from './sbom.parser';

const component: ResolvedComponent = {
  purl: 'pkg:npm/express@4.17.1',
  name: 'express',
  version: '4.17.1',
  ecosystem: 'npm',
  direct: true,
  dependencyPath: [],
  licenses: [],
};

function stubOsv(body: unknown, status = 200): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(body), { status })),
  );
}

afterEach(() => vi.unstubAllGlobals());

describe('VulnMatcher.match', () => {
  it('maps an OSV vuln to a match with severity derived from the score', async () => {
    stubOsv({
      vulns: [
        {
          id: 'GHSA-hrpp-h998-j3pp',
          aliases: ['CVE-2022-24999'],
          summary: 'qs vulnerable to prototype poisoning',
          severity: [{ type: 'CVSS_V3', score: '7.5' }],
          affected: [
            {
              package: { ecosystem: 'npm' },
              ranges: [{ events: [{ introduced: '0' }, { fixed: '6.7.3' }] }],
            },
          ],
        },
      ],
    });

    const matches = await new VulnMatcher().match(component);
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({
      id: 'GHSA-hrpp-h998-j3pp',
      source: 'GHSA',
      severity: 'high',
      cvssScore: 7.5,
      fixedVersion: '6.7.3',
      kev: false,
    });
  });

  it('ignores fixed versions from other ecosystems', async () => {
    stubOsv({
      vulns: [
        {
          id: 'CVE-2020-0001',
          affected: [
            {
              package: { ecosystem: 'PyPI' },
              ranges: [{ events: [{ fixed: '9.9.9' }] }],
            },
          ],
        },
      ],
    });

    const [match] = await new VulnMatcher().match(component);
    expect(match.source).toBe('CVE');
    expect(match.fixedVersion).toBeUndefined();
    // No CVSS reported → conservative middle severity rather than silence.
    expect(match.severity).toBe('medium');
  });

  it('returns no matches when OSV errors, rather than failing the scan', async () => {
    stubOsv({ message: 'rate limited' }, 429);
    expect(await new VulnMatcher().match(component)).toEqual([]);

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network down');
      }),
    );
    expect(await new VulnMatcher().match(component)).toEqual([]);
  });
});

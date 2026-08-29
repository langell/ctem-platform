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

    const { matches, mirrored } = await new VulnMatcher().match(component);
    expect(mirrored).toBe(false); // no database wired in this test
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

    const [match] = (await new VulnMatcher().match(component)).matches;
    expect(match.source).toBe('CVE');
    expect(match.fixedVersion).toBeUndefined();
    // No CVSS reported → conservative middle severity rather than silence.
    expect(match.severity).toBe('medium');
  });

  it('pages EPSS into the overlay cache and refreshes KEV on warmCache', async () => {
    const fetchFn = vi.fn(async (url: string | URL) => {
      const href = String(url);
      if (href.includes('known_exploited')) {
        return new Response(JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2022-24999' }] }), {
          status: 200,
        });
      }
      if (href.includes('epss')) {
        const offset = Number(new URL(href).searchParams.get('offset') ?? '0');
        if (offset === 0) {
          return new Response(
            JSON.stringify({
              total: 2,
              offset: 0,
              limit: 1,
              data: [{ cve: 'CVE-2022-24999', epss: '0.77', percentile: '0.99' }],
            }),
            { status: 200 },
          );
        }
        return new Response(
          JSON.stringify({
            total: 2,
            offset: 1,
            limit: 1,
            data: [{ cve: 'CVE-2020-0001', epss: '0.01' }],
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          vulns: [
            {
              id: 'GHSA-hrpp-h998-j3pp',
              aliases: ['CVE-2022-24999'],
              summary: 'qs',
              severity: [{ type: 'CVSS_V3', score: '7.5' }],
            },
          ],
        }),
        { status: 200 },
      );
    });
    vi.stubGlobal('fetch', fetchFn);

    const matcher = new VulnMatcher();
    try {
      await matcher.warmCache();
      const { matches } = await matcher.match(component);
      expect(matches[0]).toMatchObject({ epssScore: 0.77, kev: true });
      const epssCalls = fetchFn.mock.calls.filter((c) => String(c[0]).includes('epss'));
      expect(epssCalls.length).toBeGreaterThanOrEqual(2);
    } finally {
      matcher.onModuleDestroy();
    }
  });

  it('returns no matches when OSV errors, rather than failing the scan', async () => {
    stubOsv({ message: 'rate limited' }, 429);
    expect((await new VulnMatcher().match(component)).matches).toEqual([]);

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network down');
      }),
    );
    expect((await new VulnMatcher().match(component)).matches).toEqual([]);
  });
});

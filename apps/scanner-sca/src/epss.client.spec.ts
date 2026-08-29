import { describe, expect, it, vi } from 'vitest';
import { fetchEpssPaged, nextEpssOffset, parseEpssPage } from './epss.client';

describe('nextEpssOffset', () => {
  it('advances until total is covered', () => {
    const page = parseEpssPage({
      total: 3,
      offset: 0,
      limit: 2,
      data: [
        { cve: 'CVE-1', epss: '0.1' },
        { cve: 'CVE-2', epss: '0.2' },
      ],
    });
    expect(nextEpssOffset(page)).toBe(2);
    expect(nextEpssOffset(parseEpssPage({ total: 3, offset: 2, data: [{ cve: 'CVE-3', epss: '0.3' }] }))).toBeNull();
  });
});

describe('fetchEpssPaged', () => {
  it('pages a mirrored-CVE query instead of a single unpaged request', async () => {
    const fetchImpl = vi.fn(async (url: string | URL) => {
      const offset = Number(new URL(String(url)).searchParams.get('offset') ?? '0');
      return new Response(
        JSON.stringify({
          total: 2,
          offset,
          limit: 1,
          data: [{ cve: `CVE-2024-000${offset + 1}`, epss: '0.5' }],
        }),
        { status: 200 },
      );
    });

    const scores = await fetchEpssPaged({
      apiUrl: 'https://epss.test/v1/epss',
      cves: ['CVE-2024-0001', 'CVE-2024-0002'],
      pageSize: 1,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(scores.size).toBe(2);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(String(fetchImpl.mock.calls[0][0])).toContain('offset=0');
    expect(String(fetchImpl.mock.calls[1][0])).toContain('offset=1');
  });
});

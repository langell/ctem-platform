import { describe, expect, it, vi } from 'vitest';
import {
  buildEpssUrl,
  fetchEpssPaged,
  nextEpssOffset,
  parseEpssPage,
  scoresFromPage,
} from './epss.client';

describe('parseEpssPage / nextEpssOffset', () => {
  it('walks offset until total is covered', () => {
    const first = parseEpssPage({
      total: 3,
      offset: 0,
      limit: 2,
      data: [
        { cve: 'CVE-1', epss: '0.1', percentile: '0.5' },
        { cve: 'CVE-2', epss: '0.2', percentile: '0.6' },
      ],
    });
    expect(nextEpssOffset(first)).toBe(2);

    const last = parseEpssPage({
      total: 3,
      offset: 2,
      limit: 2,
      data: [{ cve: 'CVE-3', epss: '0.3' }],
    });
    expect(nextEpssOffset(last)).toBeNull();
    expect(scoresFromPage(last).get('CVE-3')).toEqual({ epss: 0.3, percentile: null });
  });

  it('stops when a page is empty even if total claims more', () => {
    expect(nextEpssOffset(parseEpssPage({ total: 100, offset: 0, limit: 100, data: [] }))).toBeNull();
  });

  it('treats a missing total as "this page is the whole result"', () => {
    const page = parseEpssPage({ data: [{ cve: 'CVE-1', epss: '0.01' }] });
    expect(page.total).toBe(1);
    expect(nextEpssOffset(page)).toBeNull();
  });
});

describe('fetchEpssPaged', () => {
  it('pages a CVE-filtered query to completion', async () => {
    const fetchImpl = vi.fn(async (url: string | URL) => {
      const offset = Number(new URL(String(url)).searchParams.get('offset') ?? '0');
      if (offset === 0) {
        return new Response(
          JSON.stringify({
            total: 2,
            offset: 0,
            limit: 1,
            data: [{ cve: 'CVE-2024-1111', epss: '0.42', percentile: '0.97' }],
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          total: 2,
          offset: 1,
          limit: 1,
          data: [{ cve: 'CVE-2024-2222', epss: '0.11', percentile: '0.40' }],
        }),
        { status: 200 },
      );
    });

    const scores = await fetchEpssPaged({
      apiUrl: 'https://epss.test/v1/epss',
      cves: ['CVE-2024-1111', 'CVE-2024-2222', 'GHSA-skip-me'],
      pageSize: 1,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect(scores.get('CVE-2024-1111')).toEqual({ epss: 0.42, percentile: 0.97 });
    expect(scores.get('CVE-2024-2222')).toEqual({ epss: 0.11, percentile: 0.4 });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(String(fetchImpl.mock.calls[0][0])).toContain('offset=0');
    expect(String(fetchImpl.mock.calls[1][0])).toContain('offset=1');
  });

  it('skips a failed page and keeps scores already collected', async () => {
    const onPageError = vi.fn();
    const fetchImpl = vi.fn(async (url: string | URL) => {
      const offset = Number(new URL(String(url)).searchParams.get('offset') ?? '0');
      if (offset === 0) {
        return new Response(
          JSON.stringify({
            total: 2,
            offset: 0,
            limit: 1,
            data: [{ cve: 'CVE-2024-0001', epss: '0.9', percentile: '0.99' }],
          }),
          { status: 200 },
        );
      }
      return new Response('nope', { status: 503 });
    });

    const scores = await fetchEpssPaged({
      apiUrl: 'https://epss.test/v1/epss',
      pageSize: 1,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      onPageError,
    });

    expect(scores.get('CVE-2024-0001')).toEqual({ epss: 0.9, percentile: 0.99 });
    expect(onPageError).toHaveBeenCalledWith(503, expect.stringContaining('offset=1'));
  });

  it('pages the unfiltered catalog when no CVE list is given', async () => {
    const fetchImpl = vi.fn(async (url: string | URL) => {
      const offset = Number(new URL(String(url)).searchParams.get('offset') ?? '0');
      return new Response(
        JSON.stringify({
          total: 2,
          offset,
          limit: 1,
          data: [{ cve: `CVE-PAGE-${offset}`, epss: '0.01' }],
        }),
        { status: 200 },
      );
    });

    const scores = await fetchEpssPaged({
      apiUrl: 'https://epss.test/v1/epss',
      pageSize: 1,
      maxPages: 2,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    expect([...scores.keys()]).toEqual(['CVE-PAGE-0', 'CVE-PAGE-1']);
  });
});

describe('buildEpssUrl', () => {
  it('preserves the path and appends paging params', () => {
    const url = buildEpssUrl('https://api.first.org/data/v1/epss', { limit: '100', offset: '200' });
    expect(url).toContain('/data/v1/epss');
    expect(url).toContain('limit=100');
    expect(url).toContain('offset=200');
  });
});

/**
 * Paged EPSS client for the matcher cache. FIRST's API defaults to 100 rows
 * and will silently truncate a single unpaged request, so we walk `offset`
 * until `total` is covered (or a page cap is hit).
 */

export const EPSS_PAGE_SIZE = 100;
export const EPSS_CVE_BATCH = 80;
export const EPSS_MAX_PAGES = 50;

export interface EpssScore {
  epss: number;
  percentile: number | null;
}

export interface EpssPage {
  total: number;
  offset: number;
  limit: number;
  data: Array<{ cve: string; epss: string; percentile?: string }>;
}

export function parseEpssPage(body: unknown): EpssPage {
  const raw = (body ?? {}) as {
    total?: number;
    offset?: number;
    limit?: number;
    data?: Array<{ cve: string; epss: string; percentile?: string }>;
  };
  const data = raw.data ?? [];
  return {
    total: raw.total ?? data.length,
    offset: raw.offset ?? 0,
    limit: raw.limit ?? data.length,
    data,
  };
}

export function nextEpssOffset(page: EpssPage): number | null {
  if (!page.data.length) return null;
  const next = page.offset + page.data.length;
  return next < page.total ? next : null;
}

export interface EpssFetchOptions {
  apiUrl: string;
  cves?: string[];
  maxPages?: number;
  pageSize?: number;
  fetchImpl?: typeof fetch;
  onPageError?: (status: number) => void;
}

export async function fetchEpssPaged(opts: EpssFetchOptions): Promise<Map<string, EpssScore>> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const maxPages = opts.maxPages ?? EPSS_MAX_PAGES;
  const pageSize = opts.pageSize ?? EPSS_PAGE_SIZE;
  const scores = new Map<string, EpssScore>();

  if (opts.cves) {
    const unique = [...new Set(opts.cves.filter((c) => c.startsWith('CVE-')))];
    for (let i = 0; i < unique.length; i += EPSS_CVE_BATCH) {
      await pageQuery(
        opts.apiUrl,
        { cve: unique.slice(i, i + EPSS_CVE_BATCH).join(',') },
        { fetchImpl, maxPages, pageSize, onPageError: opts.onPageError, into: scores },
      );
    }
    return scores;
  }

  await pageQuery(opts.apiUrl, {}, { fetchImpl, maxPages, pageSize, onPageError: opts.onPageError, into: scores });
  return scores;
}

async function pageQuery(
  apiUrl: string,
  extra: Record<string, string>,
  ctx: {
    fetchImpl: typeof fetch;
    maxPages: number;
    pageSize: number;
    onPageError?: (status: number) => void;
    into: Map<string, EpssScore>;
  },
): Promise<void> {
  let offset = 0;
  for (let pageNum = 0; pageNum < ctx.maxPages; pageNum++) {
    const url = new URL(apiUrl);
    for (const [key, value] of Object.entries({ ...extra, limit: String(ctx.pageSize), offset: String(offset) })) {
      url.searchParams.set(key, value);
    }
    const res = await ctx.fetchImpl(url.toString(), { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) {
      ctx.onPageError?.(res.status);
      break;
    }
    const page = parseEpssPage(await res.json());
    for (const entry of page.data) {
      ctx.into.set(entry.cve, {
        epss: Number(entry.epss),
        percentile: entry.percentile != null && entry.percentile !== '' ? Number(entry.percentile) : null,
      });
    }
    const next = nextEpssOffset(page);
    if (next == null) break;
    offset = next;
  }
}

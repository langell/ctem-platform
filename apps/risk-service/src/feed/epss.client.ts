/**
 * Paged EPSS client. FIRST's API defaults to 100 rows and will silently
 * truncate a single unpaged request, so every caller walks `offset` until
 * `total` is covered (or a page cap is hit).
 */
import { chunk } from './enrichment.logic';

/** FIRST's documented page size. */
export const EPSS_PAGE_SIZE = 100;
/** CVE-filter batch — keeps the query string well under URL limits. */
export const EPSS_CVE_BATCH = 80;
/** Guard against a runaway catalog crawl. */
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

/** Next offset, or null when this page exhausted the result set. */
export function nextEpssOffset(page: EpssPage): number | null {
  if (!page.data.length) return null;
  const next = page.offset + page.data.length;
  return next < page.total ? next : null;
}

export function scoresFromPage(page: EpssPage): Map<string, EpssScore> {
  const scores = new Map<string, EpssScore>();
  for (const entry of page.data) {
    scores.set(entry.cve, {
      epss: Number(entry.epss),
      percentile: entry.percentile != null && entry.percentile !== '' ? Number(entry.percentile) : null,
    });
  }
  return scores;
}

export interface EpssFetchOptions {
  apiUrl: string;
  /** When set, only these CVEs are requested (complete coverage of a mirror). */
  cves?: string[];
  maxPages?: number;
  pageSize?: number;
  fetchImpl?: typeof fetch;
  onPageError?: (status: number, url: string) => void;
}

/**
 * Pages the EPSS API into a CVE → score map. Prefers a CVE-filtered crawl
 * (complete coverage of mirrored advisories) over a full-catalog dump.
 */
export async function fetchEpssPaged(opts: EpssFetchOptions): Promise<Map<string, EpssScore>> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const maxPages = opts.maxPages ?? EPSS_MAX_PAGES;
  const pageSize = opts.pageSize ?? EPSS_PAGE_SIZE;
  const scores = new Map<string, EpssScore>();

  if (opts.cves) {
    const unique = [...new Set(opts.cves.filter((c) => c.startsWith('CVE-')))];
    for (const batch of chunk(unique, EPSS_CVE_BATCH)) {
      await pageQuery(
        opts.apiUrl,
        { cve: batch.join(',') },
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
    onPageError?: (status: number, url: string) => void;
    into: Map<string, EpssScore>;
  },
): Promise<void> {
  let offset = 0;
  for (let pageNum = 0; pageNum < ctx.maxPages; pageNum++) {
    const url = buildEpssUrl(apiUrl, { ...extra, limit: String(ctx.pageSize), offset: String(offset) });
    const res = await ctx.fetchImpl(url, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) {
      ctx.onPageError?.(res.status, url);
      break;
    }
    const page = parseEpssPage(await res.json());
    for (const [cve, score] of scoresFromPage(page)) ctx.into.set(cve, score);
    const next = nextEpssOffset(page);
    if (next == null) break;
    offset = next;
  }
}

export function buildEpssUrl(apiUrl: string, params: Record<string, string>): string {
  const url = new URL(apiUrl);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return url.toString();
}

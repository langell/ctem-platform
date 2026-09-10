export class CspmScanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CspmScanError';
  }
}

export const CSPM_MAX_PAGES = 20;
export const CSPM_PER_PAGE = 100;

const MUTATING_METHODS = new Set(['PUT', 'PATCH', 'DELETE', 'CONNECT', 'TRACE']);

/** AWS Query actions this scanner may POST. Everything else is refused. */
const AWS_READ_ACTIONS = new Set(['GetCallerIdentity', 'DescribeSecurityGroups']);

export interface RecordedCloudCall {
  method: string;
  url: string;
  body?: string;
}

export type CloudFetch = (
  url: string | URL,
  init?: RequestInit,
) => Promise<Response>;

/**
 * Wrap fetch: allowlisted URLs only, no mutating verbs, record every call
 * so tests can prove we never Put/Delete/Create.
 */
export function guardedFetch(impl: CloudFetch, calls: RecordedCloudCall[]): CloudFetch {
  return async (url, init) => {
    const method = (init?.method ?? 'GET').toUpperCase();
    if (MUTATING_METHODS.has(method)) {
      throw new CspmScanError(
        `Refusing mutating cloud API ${method} ${String(url)} — cloud posture is read-only`,
      );
    }
    if (method !== 'GET' && method !== 'POST') {
      throw new CspmScanError(
        `Refusing cloud API ${method} ${String(url)} — cloud posture is read-only GET/POST`,
      );
    }
    const body = typeof init?.body === 'string' ? init.body : undefined;
    if (method === 'POST' && body) {
      assertReadOnlyPost(String(url), body);
    }
    calls.push({ method, url: String(url), body });
    return impl(url, init);
  };
}

function assertReadOnlyPost(url: string, body: string): void {
  const host = safeHost(url);
  // OAuth token exchanges are POST but not cloud-resource mutations.
  if (host === 'oauth2.googleapis.com' || host === 'login.microsoftonline.com') {
    if (body.includes('grant_type=')) return;
    throw new CspmScanError('Refusing non-token POST on identity host');
  }
  if (host.endsWith('.amazonaws.com') || host === 'amazonaws.com') {
    const params = new URLSearchParams(body);
    const action = params.get('Action') ?? '';
    if (!AWS_READ_ACTIONS.has(action)) {
      throw new CspmScanError(
        `Refusing AWS Action '${action || '<missing>'}' — cloud posture is read-only`,
      );
    }
    return;
  }
  throw new CspmScanError(`Refusing POST to '${host}' — cloud posture is read-only`);
}

function safeHost(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

export function failTruncated(label: string): never {
  throw new CspmScanError(
    `Cloud posture listing truncated at ${CSPM_MAX_PAGES * CSPM_PER_PAGE} ${label} (page cap ${CSPM_MAX_PAGES}); refusing empty success`,
  );
}

export function failIncompletePage(label: string): never {
  throw new CspmScanError(
    `Incomplete ${label} API page — truncated without a next token; refusing empty success`,
  );
}

export async function walkPages<T>(args: {
  label: string;
  fetchPage: (token: string | undefined) => Promise<T>;
  nextToken: (page: T) => string | undefined;
  isTruncated?: (page: T) => boolean;
  onPage: (page: T) => void;
}): Promise<void> {
  let token: string | undefined;
  for (let page = 1; page <= CSPM_MAX_PAGES; page++) {
    const body = await args.fetchPage(token);
    const truncated = args.isTruncated?.(body) === true;
    const next = args.nextToken(body);
    if (truncated && !next) failIncompletePage(args.label);
    args.onPage(body);
    if (!next) return;
    if (page === CSPM_MAX_PAGES) failTruncated(args.label);
    token = next;
  }
}

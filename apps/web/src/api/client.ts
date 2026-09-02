/**
 * Gateway HTTP client. The UI talks to /v1 on the api-gateway only.
 *
 * The browser session is the issued JWT. Machine PATs never go in
 * sessionStorage — they authenticate as Authorization on the gateway only.
 * Org is never sent: no x-ctem-org, no orgId query, no org field on the body.
 * The gateway reads org_id from the JWT (or the PAT record) and that is the
 * only tenant the request can see.
 */

export const TOKEN_STORAGE_KEY = 'ctem.gateway.token';
const PAT_PREFIX = 'ctem_pat_';

/** Machine PATs authenticate as Authorization on the gateway — never in the UI. */
export function isPatToken(token: string): boolean {
  return token.trim().startsWith(PAT_PREFIX);
}

/** Names a client must never send as a header, query key, or body field. */
export const FORBIDDEN_ORG_KEYS = [
  'orgid',
  'org_id',
  'organizationid',
  'organization_id',
  'x-ctem-org',
  'x-org-id',
];

export function isForbiddenOrgKey(key: string): boolean {
  return FORBIDDEN_ORG_KEYS.includes(key.toLowerCase());
}

export class GatewayError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly body: unknown = null,
  ) {
    super(message);
    this.name = 'GatewayError';
  }
}

export function tokenStore(storage: Storage | undefined = defaultStorage()): {
  get(): string | null;
  set(token: string): void;
  clear(): void;
} {
  return {
    get: () => storage?.getItem(TOKEN_STORAGE_KEY) ?? null,
    set: (token: string) => {
      const value = token.trim();
      if (isPatToken(value)) {
        throw new Error('Refusing to store a PAT in the browser session');
      }
      storage?.setItem(TOKEN_STORAGE_KEY, value);
    },
    clear: () => storage?.removeItem(TOKEN_STORAGE_KEY),
  };
}

function defaultStorage(): Storage | undefined {
  return typeof sessionStorage === 'undefined' ? undefined : sessionStorage;
}

export interface GatewayRequestInit {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  token: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
}

export interface BuiltGatewayRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

/**
 * Build a gateway request. Throws if the caller tries to attach an org
 * via header, query, or body — that is the reviewer merge bar.
 */
export function buildGatewayRequest(path: string, init: GatewayRequestInit): BuiltGatewayRequest {
  if (!path.startsWith('/v1/')) {
    throw new Error(`UI may only call gateway /v1 routes, got ${path}`);
  }

  const headers: Record<string, string> = {
    authorization: `Bearer ${init.token}`,
    accept: 'application/json',
  };
  if (init.body !== undefined) headers['content-type'] = 'application/json';

  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(init.query ?? {})) {
    if (isForbiddenOrgKey(key)) {
      throw new Error(`Refusing to send org selector as query: ${key}`);
    }
    if (value !== undefined && value !== '') params.set(key, String(value));
  }

  const qs = params.toString();
  const url = qs ? `${path}?${qs}` : path;

  if (init.body && typeof init.body === 'object') {
    for (const key of Object.keys(init.body as Record<string, unknown>)) {
      if (isForbiddenOrgKey(key)) {
        throw new Error(`Refusing to send org selector as body field: ${key}`);
      }
    }
  }

  assertNoOrgLeak({ url, headers, body: init.body });

  return {
    url,
    method: init.method ?? 'GET',
    headers,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  };
}

export function assertNoOrgLeak(input: {
  url: string;
  headers: Record<string, string>;
  body?: unknown;
}): void {
  for (const key of Object.keys(input.headers)) {
    if (isForbiddenOrgKey(key)) {
      throw new Error(`Refusing to send org selector as header: ${key}`);
    }
  }
  const query = input.url.split('?')[1] ?? '';
  for (const pair of query.split('&')) {
    const key = decodeURIComponent(pair.split('=')[0] ?? '');
    if (key && isForbiddenOrgKey(key)) {
      throw new Error(`Refusing to send org selector as query: ${key}`);
    }
  }
}

export async function gatewayFetch<T>(
  path: string,
  init: Omit<GatewayRequestInit, 'token'> & { token?: string } = {},
): Promise<T> {
  const token = init.token ?? tokenStore().get();
  if (!token) throw new GatewayError(401, 'Not signed in');

  const req = buildGatewayRequest(path, { ...init, token });
  const res = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body });
  const payload = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    const title =
      (payload as { title?: string; detail?: string } | null)?.title ??
      (payload as { detail?: string } | null)?.detail ??
      `Gateway error ${res.status}`;
    throw new GatewayError(res.status, title, payload);
  }
  return payload as T;
}

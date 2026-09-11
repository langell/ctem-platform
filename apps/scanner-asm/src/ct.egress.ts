/**
 * Certificate Transparency egress for ASM subdomain enumeration.
 *
 * Caps (code-owned, not tenant-tunable):
 * - Destination is exactly `https://crt.sh` on port 443. No tenant baseUrl,
 *   CT endpoint, DoH URL, or paid CT API.
 * - Max 3 CT pages; leftover `Link: rel=next` after the cap fails the job
 *   (incomplete scope — do not empty-succeed on truncated CT).
 * - Max 1 MiB response body per page; a size-cap hit before `end` fails the job.
 * - 8s per CT request; 20s wall budget for CT + NS collection.
 * - At most 200 discovered names (deduped, under the apex suffix).
 *
 * DNS uses the OS resolver only (`resolveNs` / `resolve4` / `resolve6`).
 * Tenant wordlists, port lists, and CT query URLs are ignored, never executed.
 * There is no built-in brute-force prefix list — sources are CT + apex NS.
 */

export const CRT_SH_HOST = 'crt.sh';
export const CRT_SH_ORIGIN = 'https://crt.sh';

export const ASM_ENUM_MAX_NAMES = 200;
export const ASM_CT_MAX_PAGES = 3;
export const ASM_CT_MAX_RESPONSE_BYTES = 1_048_576;
export const ASM_CT_TIMEOUT_MS = 8_000;
export const ASM_ENUM_BUDGET_MS = 20_000;

export class AsmCtEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AsmCtEgressError';
  }
}

/** Keys a tenant might use to point enum at a non-crt.sh host or a wordlist. */
export const TENANT_ENUM_OVERRIDE_KEYS = [
  'wordlist',
  'wordlists',
  'wordList',
  'wordLists',
  'prefixes',
  'prefixList',
  'ports',
  'portList',
  'portLists',
  'extraPorts',
  'ctUrl',
  'ctEndpoint',
  'ctQueryUrl',
  'crtshUrl',
  'crtShUrl',
  'baseUrl',
  'dnsServers',
  'nameservers',
  'nameServers',
  'dohUrl',
  'doh',
  'resolver',
  'resolvers',
  'axfr',
] as const;

export function isCrtShHost(hostname: string): boolean {
  return hostname.toLowerCase().replace(/\.$/, '') === CRT_SH_HOST;
}

/**
 * Canonicalize a CT URL. Throws rather than returning a host we must not
 * contact. Exact host `crt.sh`, https, port 443, no userinfo.
 */
export function allowlistedCrtShUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new AsmCtEgressError('Refusing unparseable CT URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new AsmCtEgressError(
      `Refusing non-https CT URL — only ${CRT_SH_ORIGIN} is permitted`,
    );
  }
  if (!isCrtShHost(parsed.hostname)) {
    throw new AsmCtEgressError(
      `Refusing CT host '${parsed.hostname}' — only ${CRT_SH_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new AsmCtEgressError('Refusing CT URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new AsmCtEgressError('Refusing CT URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  return `https://${CRT_SH_HOST}${path}${parsed.search}`;
}

/** Identity search for `%.apex` as crt.sh JSON. */
export function crtShQueryUrl(apex: string): string {
  const q = `%.${apex}`;
  return allowlistedCrtShUrl(
    `${CRT_SH_ORIGIN}/?q=${encodeURIComponent(q)}&output=json`,
  );
}

/** Complete-signal is Link rel=next, not page length. */
export function nextRelFromLinkHeader(link: string | null | undefined): string | undefined {
  if (!link || typeof link !== 'string') return undefined;
  for (const part of link.split(',')) {
    const match = part.match(/<([^>]+)>\s*;\s*rel\s*=\s*"?next"?/i);
    const href = match?.[1]?.trim();
    if (href) return href;
  }
  return undefined;
}

export function ignoredTenantEnumKeys(config: Record<string, unknown>): string[] {
  const ignored: string[] = [];
  for (const key of TENANT_ENUM_OVERRIDE_KEYS) {
    const value = config[key];
    if (value != null && value !== '') ignored.push(key);
  }
  return ignored;
}

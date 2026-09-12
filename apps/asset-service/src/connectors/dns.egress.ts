/**
 * DNS inventory egress (CTE dns_enum). Certificate Transparency is exact host
 * `crt.sh` on https/443. DNS is the OS resolver only (`resolve4` / `resolve6` /
 * `resolveCname` / `resolveNs`). No DoH, no tenant nameserver, no AXFR, no
 * free-form HTTP DNS API.
 *
 * Caps (code-owned, not tenant-tunable):
 * - Destination is exactly `https://crt.sh` on port 443. No tenant baseUrl,
 *   CT endpoint, DoH URL, or paid CT API.
 * - Max 3 CT pages; leftover `Link: rel=next` after the cap fails the sync
 *   (incomplete inventory — do not archiveStale on truncated CT).
 * - Max 1 MiB response body per page; a size-cap hit before `end` fails the sync.
 * - 8s per CT request; 20s wall budget for CT + NS collection per apex.
 * - At most 200 discovered names per apex (deduped, under the apex suffix).
 */

import { isIP } from 'node:net';
import { request as httpsRequest } from 'node:https';

export const CRT_SH_HOST = 'crt.sh';
export const CRT_SH_ORIGIN = 'https://crt.sh';

export const DNS_ENUM_MAX_NAMES = 200;
export const DNS_CT_MAX_PAGES = 3;
export const DNS_CT_MAX_RESPONSE_BYTES = 1_048_576;
export const DNS_CT_TIMEOUT_MS = 8_000;
export const DNS_ENUM_BUDGET_MS = 20_000;

export class DnsEgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DnsEgressError';
  }
}

/**
 * Keys a tenant might use to point inventory at a recursive resolver, DoH,
 * AXFR nameserver, free-form HTTP DNS API, or a non-crt.sh CT host.
 */
export const TENANT_DNS_DIAL_KEYS = [
  'nameserver',
  'nameservers',
  'nameServer',
  'nameServers',
  'dnsServer',
  'dnsServers',
  'dns_server',
  'dns_servers',
  'resolver',
  'resolvers',
  'doh',
  'dohUrl',
  'dohEndpoint',
  'doh_url',
  'baseUrl',
  'endpoint',
  'host',
  'apiUrl',
  'apiEndpoint',
  'url',
  'endpointUrl',
  'customEndpoint',
  'apiHost',
  'axfr',
  'axfrUrl',
  'axfrEndpoint',
  'wordlist',
  'wordlists',
  'wordList',
  'wordLists',
  'prefixes',
  'prefixList',
  'prefixPack',
  'ctUrl',
  'ctEndpoint',
  'ctQueryUrl',
  'crtshUrl',
  'crtShUrl',
  'crtsh',
  'whoisUrl',
  'whoisEndpoint',
] as const;

/** GitLab-style extra-host allowlist. DNS inventory refuses this entirely. */
export const EXTRA_HOST_KEY_RE = /^EXTRA_.+_HOST(_KEYS)?$/i;

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
    throw new DnsEgressError('Refusing unparseable CT URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new DnsEgressError(
      `Refusing non-https CT URL — only ${CRT_SH_ORIGIN} is permitted`,
    );
  }
  if (!isCrtShHost(parsed.hostname)) {
    throw new DnsEgressError(
      `Refusing CT host '${parsed.hostname}' — only ${CRT_SH_HOST} is allowlisted`,
    );
  }
  if (parsed.port && parsed.port !== '443') {
    throw new DnsEgressError('Refusing CT URL with a non-default port');
  }
  if (parsed.username || parsed.password) {
    throw new DnsEgressError('Refusing CT URL that embeds userinfo');
  }
  const path = parsed.pathname || '/';
  return `https://${CRT_SH_HOST}${path}${parsed.search}`;
}

/** Identity search for `%.apex` as crt.sh JSON. */
export function crtShQueryUrl(apex: string): string {
  const q = `%.${apex}`;
  return allowlistedCrtShUrl(`${CRT_SH_ORIGIN}/?q=${encodeURIComponent(q)}&output=json`);
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

function valueIsSet(value: unknown): boolean {
  return value != null && value !== '';
}

/**
 * Tenant-writable integration config must never choose a DNS server, DoH
 * endpoint, AXFR nameserver, HTTP DNS API, or CT URL. Apex labels only.
 */
export function refuseTenantDnsDial(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (EXTRA_HOST_KEY_RE.test(key) && valueIsSet(config[key])) {
      throw new DnsEgressError(
        `Refusing tenant-writable DNS endpoint (${key}) — EXTRA_*_HOST_KEYS is not permitted`,
      );
    }
  }
  for (const key of TENANT_DNS_DIAL_KEYS) {
    if (valueIsSet(config[key])) {
      throw new DnsEgressError(
        `Refusing tenant-writable DNS endpoint (${key}) — resolver is the OS only; CT is exact host crt.sh`,
      );
    }
  }
}

export function isIpLiteral(host: string): boolean {
  return isIP(host) !== 0;
}

export function isValidHostname(host: string): boolean {
  if (host.length > 253 || host === '') return false;
  const labels = host.split('.');
  if (labels.some((l) => l.length === 0)) return false;
  for (const label of labels) {
    if (label.length > 63) return false;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(label)) return false;
  }
  return true;
}

/** FQDN apex: at least two hostname labels, no IP, no URL, no wildcard. */
export function normalizeApexFqdn(raw: string): string {
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) {
    throw new DnsEgressError('Refusing empty apex — FQDN apex labels only');
  }
  if (/^https?:\/\//i.test(trimmed) || trimmed.includes('/') || trimmed.includes('@')) {
    throw new DnsEgressError(
      `Refusing apex '${raw}' — FQDN apex labels only (not a URL or nameserver)`,
    );
  }
  const host = trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;
  if (!host) {
    throw new DnsEgressError('Refusing empty apex — FQDN apex labels only');
  }
  if (isIpLiteral(host)) {
    throw new DnsEgressError(`Refusing IP-literal apex '${host}'`);
  }
  if (host.startsWith('*.') || host.includes('*')) {
    throw new DnsEgressError(`Refusing wildcard apex '${host}'`);
  }
  if (!isValidHostname(host) || host.split('.').length < 2) {
    throw new DnsEgressError(`Refusing apex '${host}' — FQDN apex labels only`);
  }
  return host;
}

/**
 * Keep names that are the apex or a suffix of it. Wildcard CT rows become the
 * bare name. Outside-suffix and IP literals are dropped (not minted).
 */
export function normalizeDiscoveredName(raw: string, apex: string): string | null {
  let name = raw.trim().toLowerCase();
  if (!name) return null;
  while (name.startsWith('*.')) name = name.slice(2);
  if (name.endsWith('.')) name = name.slice(0, -1);
  if (!name) return null;
  if (name.includes('@') || name.includes('%')) return null;
  if (isIpLiteral(name)) return null;
  if (!isValidHostname(name)) return null;
  if (name !== apex && !name.endsWith(`.${apex}`)) return null;
  return name;
}

export function namesFromCrtShBody(body: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new DnsEgressError('DNS CT response was not JSON — refusing incomplete inventory');
  }
  if (!Array.isArray(parsed)) {
    throw new DnsEgressError('DNS CT response was not a JSON array — refusing incomplete inventory');
  }
  const names: string[] = [];
  for (const row of parsed) {
    if (!row || typeof row !== 'object') continue;
    const rec = row as Record<string, unknown>;
    for (const key of ['name_value', 'common_name'] as const) {
      const v = rec[key];
      if (typeof v === 'string') names.push(...v.split(/[\s,;]+/));
    }
  }
  return names;
}

export function headerValue(
  headers: NodeJS.Dict<string | string[] | undefined>,
  name: string,
): string | undefined {
  const raw = headers[name] ?? headers[name.toLowerCase()];
  if (typeof raw === 'string') return raw;
  if (Array.isArray(raw)) return raw.join(', ');
  return undefined;
}

export function isPublicAddress(ip: string): boolean {
  if (isIP(ip) === 4) return isPublicIPv4(ip);
  if (isIP(ip) === 6) return isPublicIPv6(ip);
  throw new DnsEgressError(`DNS refused malformed IP address: ${ip}`);
}

function parseIPv4(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
}

function inIPv4Prefix(ip: number, prefix: number, prefixLen: number): boolean {
  const shift = 32 - prefixLen;
  return (ip >>> shift) === (prefix >>> shift);
}

function isPublicIPv4(ip: string): boolean {
  const n = parseIPv4(ip);
  if (n === null) throw new DnsEgressError(`DNS refused malformed IPv4: ${ip}`);

  if (inIPv4Prefix(n, 0x0a000000, 8)) return false; // 10/8
  if (inIPv4Prefix(n, 0xac100000, 12)) return false; // 172.16/12
  if (inIPv4Prefix(n, 0xc0a80000, 16)) return false; // 192.168/16
  if (inIPv4Prefix(n, 0x7f000000, 8)) return false; // 127/8
  if (inIPv4Prefix(n, 0xa9fe0000, 16)) return false; // 169.254/16
  if (inIPv4Prefix(n, 0x64400000, 10)) return false; // 100.64/10
  if (inIPv4Prefix(n, 0x00000000, 8)) return false; // 0/8
  if (inIPv4Prefix(n, 0xe0000000, 4)) return false; // 224/4
  if (inIPv4Prefix(n, 0xf0000000, 4)) return false; // 240/4
  if (inIPv4Prefix(n, 0xc0000200, 24)) return false; // 192.0.2/24
  if (inIPv4Prefix(n, 0xc6336400, 24)) return false; // 198.51.100/24
  if (inIPv4Prefix(n, 0xcb007100, 24)) return false; // 203.0.113/24
  if (ip === '169.254.169.254') return false;
  if (inIPv4Prefix(n, 0xc0000000, 24)) return false; // 192.0.0.0/24
  if (inIPv4Prefix(n, 0xc0586300, 24)) return false; // 192.88.99.0/24
  return true;
}

function parseIPv6ToBigInt(ip: string): bigint | null {
  let s = ip.trim();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (s.includes('%')) return null;

  const lower = s.toLowerCase();
  if (!lower.includes(':')) return null;

  let left: string;
  let right: string;
  let ipv4Tail: string | null = null;
  const parts: string[] = [];
  const hasIpv4Tail = lower.includes('.');

  if (lower.includes('::')) {
    const split = lower.split('::');
    if (split.length !== 2) return null;
    [left, right] = split;
    const leftParts = left ? left.split(':') : [];
    const rightParts = right ? right.split(':') : [];

    if (hasIpv4Tail) {
      const rightLast = rightParts[rightParts.length - 1];
      ipv4Tail = rightLast ?? null;
      rightParts.splice(rightParts.length - 1, 1);
    }

    const leftGroups = leftParts.filter(Boolean);
    const rightGroups = rightParts.filter(Boolean);
    const totalGroups = leftGroups.length + rightGroups.length + (ipv4Tail ? 2 : 0);
    if (totalGroups > 8) return null;
    const zeroGroups = 8 - totalGroups;
    const expanded = [...leftGroups, ...new Array(zeroGroups).fill('0'), ...rightGroups];
    if (ipv4Tail) {
      const { hi, lo } = parseIPv4ToTwo16(ipv4Tail);
      expanded.push(hi.toString(16), lo.toString(16));
    }
    parts.push(...expanded);
  } else {
    const split = lower.split(':');
    if (hasIpv4Tail) {
      const last = split[split.length - 1];
      ipv4Tail = last ?? null;
      split.splice(split.length - 1, 1);
    }
    if (split.length + (ipv4Tail ? 2 : 0) !== 8) return null;
    for (const p of split) parts.push(p);
    if (ipv4Tail) {
      const { hi, lo } = parseIPv4ToTwo16(ipv4Tail);
      parts.push(hi.toString(16), lo.toString(16));
    }
  }

  if (parts.length !== 8) return null;

  let out = 0n;
  for (const part of parts) {
    const n = parseInt(part, 16);
    if (!Number.isFinite(n) || n < 0 || n > 0xffff) return null;
    out = (out << 16n) | BigInt(n);
  }
  return out;
}

function parseIPv4ToTwo16(ipv4: string): { hi: number; lo: number } {
  const n = parseIPv4(ipv4);
  if (n === null) return { hi: 0, lo: 0 };
  const hi = (n >>> 16) & 0xffff;
  const lo = n & 0xffff;
  return { hi, lo };
}

function isInBigIntPrefix(addr: bigint, prefix: bigint, prefixLen: number): boolean {
  const shift = 128n - BigInt(prefixLen);
  return (addr >> shift) === (prefix >> shift);
}

function isPublicIPv6(ip: string): boolean {
  const addr = parseIPv6ToBigInt(ip);
  if (addr === null) throw new DnsEgressError(`DNS refused malformed IPv6: ${ip}`);

  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return false;

  const v4MappedPrefix = parseIPv6ToBigInt('::ffff:0:0');
  if (v4MappedPrefix !== null && isInBigIntPrefix(addr, v4MappedPrefix, 96)) {
    const last32 = Number(addr & ((1n << 32n) - 1n));
    const bytes = [
      (last32 >>> 24) & 0xff,
      (last32 >>> 16) & 0xff,
      (last32 >>> 8) & 0xff,
      last32 & 0xff,
    ];
    return isPublicIPv4(bytes.join('.'));
  }

  const fc00Prefix = parseIPv6ToBigInt('fc00::');
  if (fc00Prefix !== null && isInBigIntPrefix(addr, fc00Prefix, 7)) return false;

  const fe80Prefix = parseIPv6ToBigInt('fe80::');
  if (fe80Prefix !== null && isInBigIntPrefix(addr, fe80Prefix, 10)) return false;

  const ff00Prefix = parseIPv6ToBigInt('ff00::');
  if (ff00Prefix !== null && isInBigIntPrefix(addr, ff00Prefix, 8)) return false;

  const db8Prefix = parseIPv6ToBigInt('2001:db8::');
  if (db8Prefix !== null && isInBigIntPrefix(addr, db8Prefix, 32)) return false;

  const teredoPrefix = parseIPv6ToBigInt('2001::');
  if (teredoPrefix !== null && isInBigIntPrefix(addr, teredoPrefix, 32)) return false;

  return true;
}

export interface CrtShHttpResult {
  statusCode: number;
  headers: NodeJS.Dict<string | string[] | undefined>;
  body: string;
  truncated: boolean;
}

export type CrtShGet = (args: {
  connectIp: string;
  path: string;
  timeoutMs: number;
  maxBytes: number;
}) => Promise<CrtShHttpResult>;

/**
 * HTTPS GET pinned to a vetted public IP with Host/SNI `crt.sh` on port 443.
 * Size-cap hits set `truncated` so the caller can fail closed.
 */
export const httpsGetCrtSh: CrtShGet = async (args) => {
  const { connectIp, path, timeoutMs, maxBytes } = args;
  if (!isPublicAddress(connectIp)) {
    throw new DnsEgressError(`DNS refused non-public CT connect IP: ${connectIp}`);
  }

  return await new Promise<CrtShHttpResult>((resolve, reject) => {
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const settle = (value: CrtShHttpResult | Error) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (value instanceof Error) reject(value);
      else resolve(value);
    };

    const req = httpsRequest(
      {
        method: 'GET',
        host: connectIp,
        port: 443,
        path,
        headers: {
          host: CRT_SH_HOST,
          accept: 'application/json',
          'accept-encoding': 'identity',
        },
        servername: CRT_SH_HOST,
        rejectUnauthorized: true,
      },
      (res) => {
        res.setEncoding('utf8');
        let body = '';
        res.on('data', (chunk: string) => {
          body += chunk;
          if (body.length > maxBytes) {
            req.destroy();
            settle({
              statusCode: res.statusCode ?? 0,
              headers: res.headers,
              body,
              truncated: true,
            });
          }
        });
        res.on('end', () => {
          settle({
            statusCode: res.statusCode ?? 0,
            headers: res.headers,
            body,
            truncated: false,
          });
        });
        res.on('error', () => {
          settle(new DnsEgressError('DNS CT response failed — refusing incomplete inventory'));
        });
      },
    );

    timer = setTimeout(() => {
      req.destroy();
      settle(new DnsEgressError('DNS CT request timed out — refusing incomplete inventory'));
    }, timeoutMs);

    req.on('error', () =>
      settle(new DnsEgressError('DNS CT request failed — refusing incomplete inventory')),
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      settle(new DnsEgressError('DNS CT request timed out — refusing incomplete inventory'));
    });
    req.end();
  });
};

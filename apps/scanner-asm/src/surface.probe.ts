import { Injectable } from '@nestjs/common';
import type { ScanContext } from '@ctem/scanner-sdk';
import { resolve4, resolve6, resolveCname, resolveNs } from 'node:dns/promises';
import { connect as netConnect, isIP } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { rootLogger } from '@ctem/observability';

type HttpMethod = 'HEAD' | 'GET';

export interface TLSMetadata {
  expiresAt: string | null;
  issuer: string | null;
  selfSigned: boolean;
}

export interface ProbeResult {
  host: string;
  addresses: string[];
  cnames: string[];
  /** A CNAME pointing at an unclaimed provider hostname = subdomain takeover. */
  danglingCname: boolean;
  openPorts: number[];
  tls: Record<number, TLSMetadata> | null;
  httpRoot: { port: number; protocol: 'http' | 'https'; usedMethod: HttpMethod } | null;
  headers: Record<string, string>;
}

/**
 * External attack surface probing. This is the CTEM capability the SCA/SAST
 * vendors mostly do not have: finding the assets nobody remembers owning.
 *
 * Everything here touches systems from the outside, so it is rate-limited,
 * scoped to verified domains, and non-intrusive by default. Confirming an
 * exposure is one thing; exploiting it without permission is another.
 */
@Injectable()
export class SurfaceProbe {
  private readonly log = rootLogger.child({ component: 'surface-probe' });

  /**
   * Everything is tenant-declared, but we probe only safe, code-owned
   * destinations. If we cannot safely probe, we throw to fail the scan.
   */
  async probe(ctx: ScanContext, target: unknown): Promise<ProbeResult> {
    const checkDeadline = ctx.checkDeadline;
    const kind = String((target as Record<string, unknown> | undefined)?.kind ?? '');
    const externalKey = String((target as Record<string, unknown> | undefined)?.externalKey ?? '');
    if (!externalKey) throw new Error('ASM missing externalKey');

    // Normalize/validate. This strips tenant schemes, ports, paths and credentials.
    const { host, isIpLiteral } = normalizeHostTarget(kind, externalKey);

    // Budgets: bounded total probe time (in addition to the worker deadline).
    const start = Date.now();
    const totalBudgetMs = 12_000;
    const budgetExceeded = () => Date.now() - start > totalBudgetMs;
    const mustHaveDeadline = () => {
      if (!checkDeadline()) throw new Error('Job deadline exceeded');
      if (budgetExceeded()) throw new Error('Probe budget exhausted');
    };

    mustHaveDeadline();

    const [addresses, cnames] = await this.resolveVettedHost(host, isIpLiteral);

    // A CNAME that resolves to nothing is the classic takeover signature.
    const danglingCname = cnames.length > 0 && addresses.length === 0;
    if (danglingCname) {
      this.log.warn({ host, cnames }, 'possible dangling CNAME');
    }

    mustHaveDeadline();

    // Bounded TCP connect scan over fixed common ports.
    const openPorts = await this.scanCommonPorts({ ctx, addresses, mustHaveDeadline });

    mustHaveDeadline();

    // TLS handshake metadata on open TLS ports.
    const tls = await this.handshakeTlsMetadata({ ctx, host, addresses, openPorts, mustHaveDeadline });

    mustHaveDeadline();

    // Exactly one HTTP HEAD at root (GET fallback only when HEAD rejected).
    const { headers, httpRoot } = await this.rootSecurityHeaderProbe({
      ctx,
      host,
      addresses,
      openPorts,
      mustHaveDeadline,
    });

    return { host, addresses, cnames, danglingCname, openPorts, tls, headers, httpRoot };
  }

  /** Enumerates subdomains from certificate transparency logs and DNS. */
  async enumerate(apexDomain: string): Promise<string[]> {
    // TODO: crt.sh / CT log query + NS record walk + optional wordlist.
    await resolveNs(apexDomain).catch(() => []);
    return [];
  }

  private async resolveVettedHost(host: string, isIpLiteral: boolean): Promise<[addresses: string[], cnames: string[]]> {
    if (isIpLiteral) {
      if (!isPublicAddress(host)) throw new Error(`ASM refused non-public target IP: ${host}`);
      return [[host], []];
    }

    const [a, aaaa] = await Promise.all([resolve4(host).catch(() => []), resolve6(host).catch(() => [])]);
    const addresses = [...a, ...aaaa];

    // SSRF bar: any resolved address must be public/global.
    for (const ip of addresses) {
      if (!isPublicAddress(ip)) throw new Error(`ASM refused non-public resolved IP: ${ip}`);
    }

    // Keep dangling-CNAME behavior, but never use it for TCP/TLS/HTTP probing.
    const cnames = await resolveCname(host).catch(() => []);
    return [addresses, cnames];
  }

  private async scanCommonPorts(args: {
    ctx: ScanContext;
    addresses: string[];
    mustHaveDeadline: () => void;
  }): Promise<number[]> {
    const { ctx, addresses, mustHaveDeadline } = args;
    const openPorts: number[] = [];

    // Connection-level timeouts are not scan failures; they are closed/filtered results.
    for (const port of COMMON_PORTS) {
      mustHaveDeadline();
      const isOpen = await tcpConnectAnyVettedIp({ ctx, ipCandidates: addresses, port });
      if (isOpen) openPorts.push(port);
    }

    return openPorts;
  }

  private async handshakeTlsMetadata(args: {
    ctx: ScanContext;
    host: string;
    addresses: string[];
    openPorts: number[];
    mustHaveDeadline: () => void;
  }): Promise<Record<number, TLSMetadata> | null> {
    const { ctx, host, addresses, openPorts, mustHaveDeadline } = args;

    const tlsPorts = openPorts.filter((p) => TLS_PORTS.includes(p));
    if (!tlsPorts.length) return null;

    const out: Record<number, TLSMetadata> = {};
    for (const port of tlsPorts) {
      mustHaveDeadline();
      const cert = await tlsHandshakeGetMetadata({ ctx, hostForSni: host, ipCandidates: addresses, port });
      if (cert) out[port] = cert;
    }

    return Object.keys(out).length ? out : null;
  }

  private async rootSecurityHeaderProbe(args: {
    ctx: ScanContext;
    host: string;
    addresses: string[];
    openPorts: number[];
    mustHaveDeadline: () => void;
  }): Promise<{ headers: Record<string, string>; httpRoot: ProbeResult['httpRoot'] }> {
    const { ctx, host, addresses, openPorts, mustHaveDeadline } = args;

    const httpsPort = openPorts.find((p) => HTTPS_PORTS.includes(p));
    const httpPort = !httpsPort ? openPorts.find((p) => HTTP_PORTS.includes(p)) : undefined;
    const port = httpsPort ?? httpPort;
    if (!port) return { headers: {}, httpRoot: null };

    // SSRF: we never connect to the hostname again; we use the already vetted IP.
    // "Exactly one HEAD" => we do not retry across multiple IPs.
    const ip = addresses[0];
    if (!ip) return { headers: {}, httpRoot: null };

    const protocol: 'http' | 'https' = httpsPort ? 'https' : 'http';
    mustHaveDeadline();

    const head = await httpRootRequest({
      ctx,
      protocol,
      method: 'HEAD',
      hostHeader: host,
      connectIp: ip,
      port,
      path: '/',
    });

    mustHaveDeadline();

    // GET fallback only when HEAD is rejected.
    let usedMethod: HttpMethod = 'HEAD';
    let res = head;
    if (head.statusCode === 405 || head.statusCode === 501) {
      mustHaveDeadline();
      usedMethod = 'GET';
      res = await httpRootRequest({
        ctx,
        protocol,
        method: 'GET',
        hostHeader: host,
        connectIp: ip,
        port,
        path: '/',
      });
    }

    mustHaveDeadline();

    const headers = res.securityHeaders;
    return { headers, httpRoot: { port, protocol, usedMethod } };
  }
}

const COMMON_PORTS = [
  80, 443, 8000, 8008, 8080, 8888, 3000, 5000, 8443, 9443, 10443,
];

const HTTP_PORTS = [80, 8000, 8008, 8080, 8888, 3000, 5000];
const HTTPS_PORTS = [443, 8443, 9443, 10443];
const TLS_PORTS = HTTPS_PORTS;

const HTTP_SECURITY_HEADER_REQUIREMENTS = [
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'x-frame-options',
  'x-xss-protection',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-resource-policy',
] as const;

const EXPIRING_WITHIN_DAYS = 30;

function normalizeHostTarget(kind: string, externalKey: string): { host: string; isIpLiteral: boolean } {
  const s = externalKey.trim();
  if (!s) throw new Error('ASM missing externalKey');

  const KNOWN_PREFIXES = ['domain', 'host', 'web_application', 'api_endpoint', 'ip_range'] as const;
  const prefixRe = new RegExp(`^(${KNOWN_PREFIXES.join('|')}):(.+)$`);
  const stripped = prefixRe.test(s) ? s.replace(prefixRe, '$2') : s;
  const candidate = stripped.trim();

  const isIpRangeKind = kind === 'ip_range' || prefixRe.test(s) && s.startsWith('ip_range:');
  if (isIpRangeKind) {
    if (candidate.includes('/')) throw new Error('ASM ip_range CIDR probing unsupported');
    if (!isIpLiteral(candidate)) throw new Error(`ASM refused non-IP ip_range target: ${candidate}`);
  }

  const { host } = stripUrlToHostAndRejectCredentials(candidate);
  const normalized = host.endsWith('.') ? host.slice(0, -1) : host;
  const lower = normalized.toLowerCase();

  if (!lower) throw new Error('ASM malformed target hostname/IP');
  if (lower.includes('@') || lower.includes('%')) throw new Error('ASM refused target with credentials/zone id');

  if (!isIpLiteral(lower) && !isValidHostname(lower)) throw new Error(`ASM refused malformed hostname: ${lower}`);
  return { host: lower, isIpLiteral: isIpLiteral(lower) };
}

function stripUrlToHostAndRejectCredentials(input: string): { host: string } {
  const s = input.trim();
  if (!s) throw new Error('ASM empty target');

  // Reject embedded credentials at earliest stage.
  if (s.includes('@')) throw new Error('ASM refused target with credentials');

  // URL parse if scheme exists.
  if (s.startsWith('http://') || s.startsWith('https://')) {
    const url = new URL(s);
    if (url.username || url.password) throw new Error('ASM refused target with credentials');
    return { host: url.hostname };
  }

  // Otherwise strip path/query/fragment and parse host[:port] (port is ignored).
  const authority = s.split(/[/?#]/)[0];
  if (!authority) throw new Error('ASM malformed target');

  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    if (end === -1) throw new Error('ASM malformed IPv6 literal');
    const ip = authority.slice(1, end);
    const rest = authority.slice(end + 1);
    if (rest && !rest.startsWith(':')) throw new Error('ASM malformed target');
    return { host: ip };
  }

  // Pure IP literal?
  if (isIpLiteral(authority)) return { host: authority };

  // Host:port (port stripped).
  const lastColon = authority.lastIndexOf(':');
  if (lastColon !== -1) {
    const maybePort = authority.slice(lastColon + 1);
    if (/^\d+$/.test(maybePort)) {
      // Ignore tenant-supplied port entirely.
      return { host: authority.slice(0, lastColon) };
    }
  }

  return { host: authority };
}

function isIpLiteral(host: string): boolean {
  return isIP(host) !== 0;
}

function isValidHostname(host: string): boolean {
  if (host.length > 253) return false;
  if (host === '') return false;
  const labels = host.split('.');
  if (labels.some((l) => l.length === 0)) return false;

  for (const label of labels) {
    if (label.length > 63) return false;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(label)) return false;
  }

  return true;
}

function isPublicAddress(ip: string): boolean {
  if (isIP(ip) === 4) return isPublicIPv4(ip);
  if (isIP(ip) === 6) return isPublicIPv6(ip);
  throw new Error(`ASM refused malformed IP address: ${ip}`);
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
  if (n === null) throw new Error(`ASM refused malformed IPv4: ${ip}`);

  // RFC1918
  if (inIPv4Prefix(n, 0x0a000000, 8)) return false; // 10/8
  if (inIPv4Prefix(n, 0xac100000, 12)) return false; // 172.16/12
  if (inIPv4Prefix(n, 0xc0a80000, 16)) return false; // 192.168/16

  // loopback
  if (inIPv4Prefix(n, 0x7f000000, 8)) return false; // 127/8

  // link-local + metadata
  if (inIPv4Prefix(n, 0xa9fe0000, 16)) return false; // 169.254/16

  // CGNAT
  if (inIPv4Prefix(n, 0x64400000, 10)) return false; // 100.64/10

  // multicast / reserved / unspecified / documentation
  if (inIPv4Prefix(n, 0x00000000, 8)) return false; // 0/8 (includes 0.0.0.0)
  if (inIPv4Prefix(n, 0xE0000000, 4)) return false; // 224/4
  if (inIPv4Prefix(n, 0xF0000000, 4)) return false; // 240/4

  // RFC5737 documentation ranges requested by prompt.
  if (inIPv4Prefix(n, 0xC0000200, 24)) return false; // 192.0.2/24
  if (inIPv4Prefix(n, 0xC6336400, 24)) return false; // 198.51.100/24
  if (inIPv4Prefix(n, 0xCB007100, 24)) return false; // 203.0.113/24

  // Explicitly block 169.254.169.254 (included by /16 but defense-in-depth).
  if (ip === '169.254.169.254') return false;

  // A few additional reserved blocks commonly abused.
  if (inIPv4Prefix(n, 0xC0000000, 24)) return false; // 192.0.0.0/24
  if (inIPv4Prefix(n, 0xC0586300, 24)) return false; // 192.88.99.0/24

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
      ipv4Tail = rightLast;
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
      ipv4Tail = last;
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
  if (addr === null) throw new Error(`ASM refused malformed IPv6: ${ip}`);

  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return false;

  // IPv4-mapped IPv6: ::ffff:w.x.y.z
  const v4MappedPrefix = parseIPv6ToBigInt('::ffff:0:0');
  if (v4MappedPrefix !== null && isInBigIntPrefix(addr, v4MappedPrefix, 96)) {
    const last32 = Number(addr & ((1n << 32n) - 1n));
    const bytes = [
      (last32 >>> 24) & 0xff,
      (last32 >>> 16) & 0xff,
      (last32 >>> 8) & 0xff,
      last32 & 0xff,
    ];
    const v4 = bytes.join('.');
    return isPublicIPv4(v4);
  }

  const fc00Prefix = parseIPv6ToBigInt('fc00::');
  if (fc00Prefix !== null && isInBigIntPrefix(addr, fc00Prefix, 7)) return false;

  const fe80Prefix = parseIPv6ToBigInt('fe80::');
  if (fe80Prefix !== null && isInBigIntPrefix(addr, fe80Prefix, 10)) return false;

  const ff00Prefix = parseIPv6ToBigInt('ff00::');
  if (ff00Prefix !== null && isInBigIntPrefix(addr, ff00Prefix, 8)) return false;

  const db8Prefix = parseIPv6ToBigInt('2001:db8::');
  if (db8Prefix !== null && isInBigIntPrefix(addr, db8Prefix, 32)) return false;

  // Conservative "other non-global ranges": Teredo (2001::/32).
  const teredoPrefix = parseIPv6ToBigInt('2001::');
  if (teredoPrefix !== null && isInBigIntPrefix(addr, teredoPrefix, 32)) return false;

  return true;
}

async function tcpConnectAnyVettedIp(args: {
  ctx: ScanContext;
  ipCandidates: string[];
  port: number;
}): Promise<boolean> {
  const { ipCandidates, port, ctx } = args;
  if (!ipCandidates.length) return false;

  const connectTimeoutMs = 700;
  for (const ip of ipCandidates) {
    ctx.checkDeadline();
    const ok = await tcpConnectOne(ip, port, connectTimeoutMs);
    if (ok) return true;
  }
  return false;
}

async function tcpConnectOne(ip: string, port: number, timeoutMs: number): Promise<boolean> {
  const socket = netConnect({ host: ip, port });

  return await new Promise<boolean>((resolve) => {
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const settle = (value: boolean) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      socket.destroy();
      resolve(value);
    };

    timer = setTimeout(() => {
      settle(false);
    }, timeoutMs);

    socket.once('connect', () => settle(true));
    socket.once('error', () => settle(false));
    socket.once('close', () => settle(false));
  });
}

async function tlsHandshakeGetMetadata(args: {
  ctx: ScanContext;
  hostForSni: string;
  ipCandidates: string[];
  port: number;
}): Promise<TLSMetadata | null> {
  const { ctx, hostForSni, ipCandidates, port } = args;
  if (!ipCandidates.length) return null;
  const timeoutMs = 1200;

  for (const ip of ipCandidates) {
    ctx.checkDeadline();

    const socket = tlsConnect({
      host: ip,
      port,
      servername: hostForSni, // Preserve original hostname for TLS SNI.
      rejectUnauthorized: false, // metadata only — do not validate/upgrade.
    });

    const result = await new Promise<TLSMetadata | null>((resolve) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(null);
      }, timeoutMs);

      const settle = (value: TLSMetadata | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolve(value);
      };

      socket.once('secureConnect', () => {
        try {
          const cert = socket.getPeerCertificate(true) as any;
          const expiresAt = cert?.valid_to ? new Date(cert.valid_to).toISOString() : null;
          const issuer = cert?.issuer ? formatCertName(cert.issuer) : null;
          const subject = cert?.subject;
          const selfSigned = Boolean(
            subject && cert?.issuer && JSON.stringify(subject) === JSON.stringify(cert.issuer),
          );
          settle({ expiresAt, issuer, selfSigned });
        } catch {
          settle(null);
        }
      });

      socket.once('error', () => settle(null));
      socket.once('close', () => settle(null));
    });

    if (result) return result;
  }

  return null;
}

async function httpRootRequest(args: {
  ctx: ScanContext;
  protocol: 'http' | 'https';
  method: HttpMethod;
  hostHeader: string;
  connectIp: string;
  port: number;
  path: string;
}): Promise<{ statusCode: number; securityHeaders: Record<string, string> }> {
  const { protocol, method, hostHeader, connectIp, port, path } = args;
  const timeoutMs = 1200;

  const transport = protocol === 'https' ? httpsRequest : httpRequest;

  return await new Promise<{ statusCode: number; securityHeaders: Record<string, string> }>((resolve) => {
    let settled = false;
    const settle = (value: { statusCode: number; securityHeaders: Record<string, string> }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };

    const timer = setTimeout(() => {
      settle({ statusCode: 0, securityHeaders: {} });
    }, timeoutMs);

    const req = transport(
      {
        method,
        host: connectIp, // connect by IP to prevent rebinding.
        port,
        path,
        headers: {
          host: hostHeader, // preserve original hostname for HTTP Host.
        },
        ...(protocol === 'https' ? { servername: hostHeader, rejectUnauthorized: false } : {}),
      },
      (res) => {
        res.setEncoding('utf8');
        res.on('data', () => undefined);
        res.on('end', () => {
          settle({ statusCode: res.statusCode ?? 0, securityHeaders: normalizeSecurityHeaders(res.headers) });
        });
      },
    );

    req.on('error', () => settle({ statusCode: 0, securityHeaders: {} }));
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error('http timeout'));
      settle({ statusCode: 0, securityHeaders: {} });
    });
    req.end();
  });
}

function normalizeSecurityHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (!HTTP_SECURITY_HEADER_REQUIREMENTS.includes(key as any)) continue;
    if (typeof v === 'string') out[key] = v;
    else if (Array.isArray(v)) out[key] = v.join(', ');
  }
  return out;
}

function formatCertName(input: Record<string, unknown>): string | null {
  const parts = Object.entries(input)
    .filter(([, v]) => typeof v === 'string' || typeof v === 'number')
    .map(([k, v]) => `${k}=${String(v)}`);
  return parts.length ? parts.join(',') : null;
}

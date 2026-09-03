import { Injectable } from '@nestjs/common';
import { BaseScanner, type ScanContext, type ScanOutcome } from '@ctem/scanner-sdk';
import type { RawFinding, ScanJob, ScannerType } from '@ctem/contracts';
import { SurfaceProbe } from './surface.probe';

/**
 * Attack surface management. Discovers and evaluates what the organization
 * exposes to the internet — including the things it forgot it exposed.
 */
@Injectable()
export class AsmScanner extends BaseScanner {
  readonly type: ScannerType = 'asm';
  readonly name = 'ctem-asm';
  readonly version = '0.1.0';

  constructor(private readonly probe: SurfaceProbe) {
    super();
  }

  supports(job: ScanJob): boolean {
    const kind = String(job.target?.kind ?? '');
    return ['domain', 'host', 'web_application', 'api_endpoint', 'ip_range'].includes(kind);
  }

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    const result = await this.probe.probe(ctx, ctx.job.target);

    const host = result.host;
    const findings: RawFinding[] = [];

    if (result.danglingCname) {
      findings.push({
        externalId: `asm.dangling-cname:${host}`,
        scannerType: 'asm',
        scannerName: this.name,
        title: `Possible subdomain takeover on ${host}`,
        description:
          `${host} has a CNAME to ${result.cnames.join(', ')} that does not resolve. ` +
          'If the target service is unclaimed, an attacker can register it and serve content from your domain.',
        severity: 'high',
        identifiers: [{ system: 'CWE', value: 'CWE-350' }],
        cvssVector: null,
        cvssScore: null,
        epssScore: null,
        kev: false,
        location: { url: host },
        fix: {
          available: true,
          guidance: 'Remove the DNS record, or reclaim the target resource at the provider.',
        },
        evidence: { cnames: result.cnames, addresses: result.addresses },
        raw: {},
      });
    }

    // Unexpected/open ports from the fixed, code-owned port list.
    for (const port of result.openPorts) {
      findings.push({
        externalId: `asm.open-port:${host}:${port}`,
        scannerType: 'asm',
        scannerName: this.name,
        title: `Unexpected open port ${port} on ${host}`,
        description: `TCP port ${port} appears open on ${host}. ASM probes only a fixed, bounded common-port list.`,
        severity: 'medium',
        identifiers: [],
        cvssVector: null,
        cvssScore: null,
        epssScore: null,
        kev: false,
        location: { url: host, port, resource: `${host}:${port}` },
        fix: { available: false, guidance: 'Restrict external exposure or close the port.' },
        evidence: { port, addresses: result.addresses },
        raw: {},
      });
    }

    // TLS certificate metadata findings.
    const tlsByPort = result.tls ?? {};
    const now = Date.now();
    const expiringMs = EXPIRING_WITHIN_DAYS * DAY_MS;

    for (const [portStr, meta] of Object.entries(tlsByPort)) {
      const port = Number(portStr);
      if (!meta) continue;

      const expiresAtMs = meta.expiresAt ? Date.parse(meta.expiresAt) : null;

      if (meta.selfSigned) {
        findings.push({
          externalId: `asm.tls-self-signed:${host}:${port}`,
          scannerType: 'asm',
          scannerName: this.name,
          title: `Self-signed TLS certificate on ${host}:${port}`,
          description: `TLS handshake to ${host}:${port} returned a self-signed certificate.`,
          severity: 'high',
          identifiers: [],
          cvssVector: null,
          cvssScore: null,
          epssScore: null,
          kev: false,
          location: { url: host, port, resource: `${host}:${port}` },
          fix: { available: false, guidance: 'Use a certificate from a trusted CA.' },
          evidence: { ...meta, expiresAtMs } as Record<string, unknown>,
          raw: {},
        });
      }

      if (expiresAtMs !== null && Number.isFinite(expiresAtMs)) {
        if (expiresAtMs < now) {
          findings.push({
            externalId: `asm.tls-expired:${host}:${port}`,
            scannerType: 'asm',
            scannerName: this.name,
            title: `Expired TLS certificate on ${host}:${port}`,
            description: `TLS certificate for ${host}:${port} expired at ${meta.expiresAt}.`,
            severity: 'high',
            identifiers: [],
            cvssVector: null,
            cvssScore: null,
            epssScore: null,
            kev: false,
            location: { url: host, port, resource: `${host}:${port}` },
            fix: { available: false, guidance: 'Renew the TLS certificate.' },
            evidence: meta as unknown as Record<string, unknown>,
            raw: {},
          });
        } else if (expiresAtMs - now <= expiringMs) {
          findings.push({
            externalId: `asm.tls-expiring:${host}:${port}`,
            scannerType: 'asm',
            scannerName: this.name,
            title: `Expiring TLS certificate on ${host}:${port}`,
            description: `TLS certificate for ${host}:${port} expires at ${meta.expiresAt}.`,
            severity: 'medium',
            identifiers: [],
            cvssVector: null,
            cvssScore: null,
            epssScore: null,
            kev: false,
            location: { url: host, port, resource: `${host}:${port}` },
            fix: { available: false, guidance: 'Renew the TLS certificate.' },
            evidence: meta as unknown as Record<string, unknown>,
            raw: {},
          });
        }
      }
    }

    // Missing security headers from the single HTTP root response.
    const httpRoot = result.httpRoot;
    if (httpRoot) {
      for (const header of SECURITY_HEADER_REQUIREMENTS) {
        if (Object.prototype.hasOwnProperty.call(result.headers, header)) continue;
        findings.push({
          externalId: `asm.missing-header:${host}:${httpRoot.port}:${header}`,
          scannerType: 'asm',
          scannerName: this.name,
          title: `Missing security header ${header} on ${host}:${httpRoot.port}`,
          description: `The ${httpRoot.usedMethod} / response did not include the ${header} security header.`,
          severity: 'medium',
          identifiers: [],
          cvssVector: null,
          cvssScore: null,
          epssScore: null,
          kev: false,
          location: { url: host, port: httpRoot.port, resource: `${host}:${httpRoot.port}` },
          fix: { available: false, guidance: `Add the ${header} header to responses.` },
          evidence: {
            httpRoot,
            missingHeader: header,
            responseHeaders: result.headers,
          },
          raw: {},
        });
      }
    }

    return {
      findings,
      rawOutput: result,
      stats: { openPorts: result.openPorts.length, addresses: result.addresses.length },
    };
  }
}

const DAY_MS = 86_400_000;
const EXPIRING_WITHIN_DAYS = 30;

const SECURITY_HEADER_REQUIREMENTS = [
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'x-frame-options',
  'x-xss-protection',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-resource-policy',
] as const;

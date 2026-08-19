import { Injectable } from '@nestjs/common';
import { BaseScanner, type ScanContext, type ScanOutcome } from '@ctem/scanner-sdk';
import type { RawFinding, ScannerType } from '@ctem/contracts';
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

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    const host = String(ctx.job.target.externalKey ?? '').replace(/^https?:\/\//, '');
    if (!host) return { findings: [], stats: {} };

    const result = await this.probe.probe(host);
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

    // TODO: expired/self-signed TLS, missing security headers, exposed admin
    // panels, unexpected open ports versus the org's declared baseline.

    return {
      findings,
      rawOutput: result,
      stats: { openPorts: result.openPorts.length, addresses: result.addresses.length },
    };
  }
}

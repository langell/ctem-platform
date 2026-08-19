import { Injectable } from '@nestjs/common';
import { resolve4, resolveCname, resolveNs } from 'node:dns/promises';
import { rootLogger } from '@ctem/observability';

export interface ProbeResult {
  host: string;
  addresses: string[];
  cnames: string[];
  /** A CNAME pointing at an unclaimed provider hostname = subdomain takeover. */
  danglingCname: boolean;
  openPorts: number[];
  tls: { expiresAt: string | null; issuer: string | null; selfSigned: boolean } | null;
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

  async probe(host: string): Promise<ProbeResult> {
    const [addresses, cnames] = await Promise.all([
      resolve4(host).catch(() => [] as string[]),
      resolveCname(host).catch(() => [] as string[]),
    ]);

    // A CNAME that resolves to nothing is the classic takeover signature.
    const danglingCname = cnames.length > 0 && addresses.length === 0;
    if (danglingCname) {
      this.log.warn({ host, cnames }, 'possible dangling CNAME');
    }

    return {
      host,
      addresses,
      cnames,
      danglingCname,
      // TODO: bounded TCP connect scan over a common-ports list, TLS handshake
      // for certificate metadata, and one HTTP HEAD for security headers.
      openPorts: [],
      tls: null,
      headers: {},
    };
  }

  /** Enumerates subdomains from certificate transparency logs and DNS. */
  async enumerate(apexDomain: string): Promise<string[]> {
    // TODO: crt.sh / CT log query + NS record walk + optional wordlist.
    await resolveNs(apexDomain).catch(() => []);
    return [];
  }
}

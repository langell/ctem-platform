import { Injectable } from '@nestjs/common';
import { resolve4, resolve6, resolveCname, resolveNs } from 'node:dns/promises';
import { z } from 'zod';
import { rootLogger } from '@ctem/observability';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { AssetConnector, DiscoveryContext } from './connector.registry';
import { resolveCredential } from './credentials';
import {
  CRT_SH_HOST,
  DNS_CT_MAX_PAGES,
  DNS_CT_MAX_RESPONSE_BYTES,
  DNS_CT_TIMEOUT_MS,
  DNS_ENUM_BUDGET_MS,
  DNS_ENUM_MAX_NAMES,
  allowlistedCrtShUrl,
  crtShQueryUrl,
  headerValue,
  httpsGetCrtSh,
  isIpLiteral,
  isPublicAddress,
  isValidHostname,
  namesFromCrtShBody,
  nextRelFromLinkHeader,
  normalizeApexFqdn,
  normalizeDiscoveredName,
  refuseTenantDnsDial,
  type CrtShGet,
} from './dns.egress';

export interface OsDnsResolver {
  resolve4(hostname: string): Promise<string[]>;
  resolve6(hostname: string): Promise<string[]>;
  resolveCname(hostname: string): Promise<string[]>;
  resolveNs(hostname: string): Promise<string[]>;
}

const nodeDns: OsDnsResolver = {
  resolve4: (hostname) => resolve4(hostname),
  resolve6: (hostname) => resolve6(hostname),
  resolveCname: (hostname) => resolveCname(hostname),
  resolveNs: (hostname) => resolveNs(hostname),
};

/**
 * Apex names only. Singular `apex` and/or `apexes[]` — FQDN labels, not a
 * nameserver URL. Forbidden dial keys are refused before this schema runs.
 */
export const DnsEnumConnectorConfig = z
  .object({
    apex: z.string().min(1).optional(),
    apexes: z.array(z.string().min(1)).optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    const raw = collectRawApexes(value);
    if (raw.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'apex or apexes is required',
        path: ['apexes'],
      });
      return;
    }
    for (const item of raw) {
      try {
        normalizeApexFqdn(item);
      } catch (err) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: err instanceof Error ? err.message : String(err),
          path: ['apexes'],
        });
      }
    }
  });
export type DnsEnumConnectorConfig = z.infer<typeof DnsEnumConnectorConfig>;

export function collectRawApexes(config: { apex?: string; apexes?: string[] }): string[] {
  const out: string[] = [];
  if (config.apex) out.push(config.apex);
  for (const item of config.apexes ?? []) out.push(item);
  return out;
}

export function configuredApexes(config: DnsEnumConnectorConfig): string[] {
  const seen = new Set<string>();
  for (const raw of collectRawApexes(config)) {
    seen.add(normalizeApexFqdn(raw));
  }
  return [...seen];
}

export function dnsExternalKey(fqdn: string): string {
  return `dns:${fqdn}`;
}

export function domainToAsset(args: {
  fqdn: string;
  apex: string;
  nameservers?: string[];
  cnames?: string[];
  addresses?: string[];
}): UpsertAssetRequest {
  const addresses = args.addresses ?? [];
  return {
    kind: 'domain',
    externalKey: dnsExternalKey(args.fqdn),
    name: args.fqdn,
    source: 'dns_enum',
    exposure: addresses.length > 0 ? 'internet_facing' : 'unknown',
    attributes: {
      apex: args.apex,
      fqdn: args.fqdn,
      nameservers: args.nameservers ?? [],
      cnames: args.cnames ?? [],
      addresses,
    },
  };
}

export interface DnsEnumConnectorDeps {
  dns?: OsDnsResolver;
  crtShGet?: CrtShGet;
}

/**
 * Domain inventory via Certificate Transparency (exact host crt.sh) and the
 * OS resolver. Complements ASM subdomain enum (findings only, no mint).
 *
 * Same persistence path as other AssetConnectors: discover → UpsertAssetRequest
 * → scheduler upsert + archiveStale scoped per integrationId. Truncated CT
 * throws so archiveStale cannot run on a partial listing.
 *
 * No credential is required. A present-but-unusable credentialRef fails closed.
 * This connector never calls SurfaceProbe.probe and never mints ip_range.
 */
@Injectable()
export class DnsEnumConnector implements AssetConnector {
  readonly provider = 'dns_enum';
  readonly assetKinds = ['domain'];
  private readonly log = rootLogger.child({ component: 'dns-enum-connector' });
  private dns: OsDnsResolver = nodeDns;
  private crtShGet: CrtShGet = httpsGetCrtSh;

  /**
   * Test seam for mocked CT HTTP / OS DNS. Production Nest construction
   * stays parameterless so DI does not try to inject a deps token.
   */
  useTestDeps(deps: DnsEnumConnectorDeps): this {
    if (deps.dns) this.dns = deps.dns;
    if (deps.crtShGet) this.crtShGet = deps.crtShGet;
    return this;
  }

  async *discover(ctx: DiscoveryContext): AsyncIterable<UpsertAssetRequest> {
    refuseTenantDnsDial(ctx.config);
    const config = DnsEnumConnectorConfig.parse(ctx.config);
    this.assertUsableCredential(ctx.credentialRef);

    const apexes = configuredApexes(config);
    let seen = 0;
    const yielded = new Set<string>();

    for (const apex of apexes) {
      for (const asset of await this.inventoryApex(apex)) {
        if (yielded.has(asset.externalKey)) continue;
        yielded.add(asset.externalKey);
        seen += 1;
        yield asset;
      }
    }

    this.log.info({ apexes: apexes.length, domains: seen }, 'dns_enum discovery complete');
  }

  /**
   * Collect the complete under-apex set, then emit. Throwing before any yield
   * for this apex keeps archiveStale from running on a truncated listing.
   */
  private async inventoryApex(apex: string): Promise<UpsertAssetRequest[]> {
    const start = Date.now();
    const mustHaveDeadline = () => {
      if (Date.now() - start > DNS_ENUM_BUDGET_MS) {
        throw new Error('DNS enum budget exhausted — refusing incomplete inventory');
      }
    };

    mustHaveDeadline();
    const fromCt = await this.collectCrtShNames(apex, mustHaveDeadline);
    mustHaveDeadline();
    const fromNs = await this.dns.resolveNs(apex).catch(() => [] as string[]);

    const names = new Set<string>([apex]);
    for (const raw of [...fromCt, ...fromNs]) {
      const name = normalizeDiscoveredName(raw, apex);
      if (name) names.add(name);
    }

    if (names.size > DNS_ENUM_MAX_NAMES) {
      throw new Error(
        `DNS listing truncated at ${DNS_ENUM_MAX_NAMES} names/apex — refusing incomplete inventory`,
      );
    }

    const assets: UpsertAssetRequest[] = [];
    for (const fqdn of [...names].sort((a, b) => a.localeCompare(b))) {
      mustHaveDeadline();
      assets.push(await this.enrichDomain(fqdn, apex));
    }
    return assets;
  }

  private async enrichDomain(fqdn: string, apex: string): Promise<UpsertAssetRequest> {
    const [a, aaaa, cnames, nameservers] = await Promise.all([
      this.dns.resolve4(fqdn).catch(() => [] as string[]),
      this.dns.resolve6(fqdn).catch(() => [] as string[]),
      this.dns.resolveCname(fqdn).catch(() => [] as string[]),
      fqdn === apex ? this.dns.resolveNs(fqdn).catch(() => [] as string[]) : Promise.resolve([] as string[]),
    ]);

    const addresses: string[] = [];
    for (const ip of [...a, ...aaaa]) {
      if (!isPublicAddress(ip)) continue;
      addresses.push(ip);
    }

    return domainToAsset({
      fqdn,
      apex,
      nameservers: nameservers.map(normalizeRecordName).filter((ns): ns is string => ns != null),
      cnames: cnames.map(normalizeRecordName).filter((c): c is string => c != null),
      addresses,
    });
  }

  private async collectCrtShNames(apex: string, mustHaveDeadline: () => void): Promise<string[]> {
    const addresses = await this.resolveCrtSh();
    const names: string[] = [];
    let url = crtShQueryUrl(apex);

    for (let page = 1; page <= DNS_CT_MAX_PAGES; page++) {
      mustHaveDeadline();
      const allowlisted = allowlistedCrtShUrl(url);
      const parsed = new URL(allowlisted);
      const path = `${parsed.pathname}${parsed.search}`;

      const res = await this.crtShGet({
        connectIp: addresses[0]!,
        path,
        timeoutMs: DNS_CT_TIMEOUT_MS,
        maxBytes: DNS_CT_MAX_RESPONSE_BYTES,
      });

      if (res.truncated) {
        throw new Error('DNS CT listing truncated at response size cap — refusing incomplete inventory');
      }
      if (res.statusCode !== 200) {
        throw new Error(`DNS CT listing HTTP ${res.statusCode} — refusing incomplete inventory`);
      }
      names.push(...namesFromCrtShBody(res.body));

      const next = nextRelFromLinkHeader(headerValue(res.headers, 'link'));
      if (!next) return names;
      if (page === DNS_CT_MAX_PAGES) {
        throw new Error('DNS CT listing truncated at page cap — refusing incomplete inventory');
      }
      url = next;
    }

    return names;
  }

  /** Resolve crt.sh via the OS resolver; refuse private/unresolved before HTTPS. */
  private async resolveCrtSh(): Promise<string[]> {
    const [a, aaaa] = await Promise.all([
      this.dns.resolve4(CRT_SH_HOST).catch(() => [] as string[]),
      this.dns.resolve6(CRT_SH_HOST).catch(() => [] as string[]),
    ]);
    const addresses = [...a, ...aaaa];
    if (!addresses.length) {
      throw new Error('DNS CT lookup failed — crt.sh did not resolve; refusing incomplete inventory');
    }
    for (const ip of addresses) {
      if (!isPublicAddress(ip)) {
        throw new Error(`DNS refused non-public resolved IP for crt.sh: ${ip}`);
      }
    }
    return addresses;
  }

  /**
   * No credential is required. A pointer that is set must resolve to a usable
   * secret — empty env / unsupported scheme / non-allowlisted env name fail
   * closed so we never empty-succeed and archiveStale.
   */
  private assertUsableCredential(credentialRef: string | null): void {
    if (!credentialRef) return;
    const secret = resolveCredential(credentialRef);
    if (!secret?.trim()) {
      throw new Error(
        `credentialRef '${credentialRef}' is set but cannot be used — refusing DNS inventory`,
      );
    }
  }
}

function normalizeRecordName(raw: string): string | null {
  const name = raw.replace(/\.$/, '').toLowerCase();
  if (!name || name.includes('/') || /^https?:/i.test(name)) return null;
  if (isIpLiteral(name) || !isValidHostname(name)) return null;
  return name;
}

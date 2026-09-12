import { afterEach, describe, expect, it, vi } from 'vitest';
import type { UpsertAssetRequest } from '@ctem/contracts';
import type { PrismaService } from '@ctem/db';
import type { DiscoveryContext } from './connector.registry';
import { ConnectorRegistry } from './connector.registry';
import { DiscoverySchedulerService } from './discovery-scheduler.service';
import {
  DnsEnumConnector,
  DnsEnumConnectorConfig,
  configuredApexes,
  dnsExternalKey,
  domainToAsset,
} from './dns.connector';
import {
  CRT_SH_HOST,
  DNS_CT_MAX_PAGES,
  DNS_ENUM_MAX_NAMES,
  type CrtShGet,
  type CrtShHttpResult,
} from './dns.egress';
import type { OsDnsResolver } from './dns.connector';

const CRT_SH_IP = '93.184.216.34';
const PUBLIC_IP = '8.8.8.8';

const ctx = (
  config: Record<string, unknown>,
  credentialRef: string | null = null,
): DiscoveryContext => ({
  orgId: 'org-1',
  integrationId: 'int-1',
  config,
  credentialRef,
  since: null,
});

async function collect(iter: AsyncIterable<UpsertAssetRequest>): Promise<UpsertAssetRequest[]> {
  const out: UpsertAssetRequest[] = [];
  for await (const item of iter) out.push(item);
  return out;
}

function mockDns(over: Partial<OsDnsResolver> = {}): OsDnsResolver {
  const table: Record<string, { a?: string[]; aaaa?: string[]; cname?: string[]; ns?: string[] }> = {
    [CRT_SH_HOST]: { a: [CRT_SH_IP] },
    'example.com': { a: [PUBLIC_IP], ns: ['ns1.example.com'] },
    'www.example.com': { a: [PUBLIC_IP], cname: ['cdn.example.net'] },
    'api.example.com': { a: ['10.0.0.5'] },
  };
  return {
    resolve4: over.resolve4 ?? (async (h) => table[h]?.a ?? []),
    resolve6: over.resolve6 ?? (async (h) => table[h]?.aaaa ?? []),
    resolveCname: over.resolveCname ?? (async (h) => table[h]?.cname ?? []),
    resolveNs: over.resolveNs ?? (async (h) => table[h]?.ns ?? []),
  };
}

function jsonResult(
  rows: unknown[],
  over: Partial<CrtShHttpResult> = {},
): CrtShHttpResult {
  return {
    statusCode: 200,
    headers: {},
    body: JSON.stringify(rows),
    truncated: false,
    ...over,
  };
}

function connector(
  crtShGet: CrtShGet,
  dns: OsDnsResolver = mockDns(),
): DnsEnumConnector {
  return new DnsEnumConnector().useTestDeps({ dns, crtShGet });
}

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
  delete process.env.GITHUB_TEST_TOKEN;
});

describe('DnsEnumConnectorConfig / externalKey', () => {
  it('accepts singular apex, list, or both and normalizes', () => {
    expect(configuredApexes(DnsEnumConnectorConfig.parse({ apex: 'Example.COM.' }))).toEqual([
      'example.com',
    ]);
    expect(configuredApexes(DnsEnumConnectorConfig.parse({ apexes: ['acme.io', 'acme.io'] }))).toEqual([
      'acme.io',
    ]);
    expect(
      configuredApexes(DnsEnumConnectorConfig.parse({ apex: 'a.example', apexes: ['b.example'] })),
    ).toEqual(['a.example', 'b.example']);
  });

  it('refuses a missing apex and a non-FQDN', () => {
    expect(() => DnsEnumConnectorConfig.parse({})).toThrow(/apex or apexes/);
    expect(() => DnsEnumConnectorConfig.parse({ apexes: ['localhost'] })).toThrow(
      /FQDN apex labels only/,
    );
  });

  it('keeps dns:{fqdn} stable across case and trailing-dot remaps', () => {
    expect(dnsExternalKey('example.com')).toBe('dns:example.com');
    expect(dnsExternalKey('www.example.com')).toBe('dns:www.example.com');
    const a = domainToAsset({ fqdn: 'www.example.com', apex: 'example.com', addresses: [PUBLIC_IP] });
    const b = domainToAsset({
      fqdn: 'www.example.com',
      apex: 'example.com',
      addresses: [PUBLIC_IP],
      cnames: ['cdn.example.net'],
    });
    expect(a.externalKey).toBe(b.externalKey);
    expect(a.kind).toBe('domain');
    expect(a.source).toBe('dns_enum');
    expect(a.exposure).toBe('internet_facing');
  });
});

describe('DnsEnumConnector.discover', () => {
  it('mints the apex and under-apex CT/NS names with public addresses only', async () => {
    const crtShGet = vi.fn<CrtShGet>(async () =>
      jsonResult([
        { name_value: 'www.example.com\napi.example.com', common_name: 'example.com' },
        { name_value: 'evil.com' },
        { name_value: 'example.com.evil.net' },
        { name_value: 'notexample.com' },
        { name_value: '*.staging.example.com' },
      ]),
    );
    const assets = await collect(
      connector(crtShGet).discover(ctx({ apexes: ['Example.COM.'] })),
    );

    expect(assets.map((a) => a.externalKey)).toEqual([
      'dns:api.example.com',
      'dns:example.com',
      'dns:ns1.example.com',
      'dns:staging.example.com',
      'dns:www.example.com',
    ]);
    expect(assets.every((a) => a.kind === 'domain' && a.source === 'dns_enum')).toBe(true);
    expect(assets.find((a) => a.externalKey === 'dns:www.example.com')?.attributes).toMatchObject({
      apex: 'example.com',
      fqdn: 'www.example.com',
      addresses: [PUBLIC_IP],
      cnames: ['cdn.example.net'],
    });
    expect(assets.find((a) => a.externalKey === 'dns:api.example.com')?.attributes).toMatchObject({
      addresses: [],
    });
    expect(assets.some((a) => a.kind === 'ip_range')).toBe(false);
    expect(JSON.stringify(assets)).not.toContain('10.0.0.5');
    expect(JSON.stringify(assets)).not.toContain('evil.com');
    expect(crtShGet).toHaveBeenCalledTimes(1);
    const call = crtShGet.mock.calls[0]![0];
    expect(call.connectIp).toBe(CRT_SH_IP);
    expect(call.path).toContain('output=json');
    expect(call.path).toContain(encodeURIComponent('%.example.com'));
  });

  it('drops outside-apex names and never mints private IPs as inventory targets', async () => {
    const dns = mockDns({
      resolve4: async (h) => {
        if (h === CRT_SH_HOST) return [CRT_SH_IP];
        if (h === 'example.com') return ['10.1.2.3'];
        return [];
      },
      resolveNs: async () => [],
    });
    const assets = await collect(
      connector(async () => jsonResult([{ name_value: 'corp.internal' }]), dns).discover(
        ctx({ apex: 'example.com' }),
      ),
    );
    expect(assets.map((a) => a.externalKey)).toEqual(['dns:example.com']);
    expect(assets[0]?.attributes?.addresses).toEqual([]);
    expect(assets[0]?.kind).toBe('domain');
  });

  it('refuses DNS-server / DoH / CT URL keys before any CT call', async () => {
    const crtShGet = vi.fn<CrtShGet>(async () => jsonResult([]));
    const dns = mockDns();
    const c = connector(crtShGet, dns);
    await expect(
      collect(c.discover(ctx({ apexes: ['example.com'], nameserver: '10.0.0.1' }))),
    ).rejects.toThrow(/tenant-writable DNS endpoint/);
    await expect(
      collect(c.discover(ctx({ apexes: ['example.com'], dohUrl: 'https://dns.google/dns-query' }))),
    ).rejects.toThrow(/tenant-writable DNS endpoint/);
    await expect(
      collect(c.discover(ctx({ apexes: ['example.com'], ctUrl: 'https://evil.example/ct' }))),
    ).rejects.toThrow(/tenant-writable DNS endpoint/);
    await expect(
      collect(c.discover(ctx({ apexes: ['example.com'], crtshUrl: 'https://crtsh.com/' }))),
    ).rejects.toThrow(/tenant-writable DNS endpoint/);
    expect(crtShGet).not.toHaveBeenCalled();
  });

  it('refuses a non-crt.sh CT next URL and does not fetch it', async () => {
    const crtShGet = vi.fn<CrtShGet>(async () =>
      jsonResult([{ name_value: 'www.example.com' }], {
        headers: { link: '<https://evil.example/ct?q=%25.example.com>; rel="next"' },
      }),
    );
    await expect(
      collect(connector(crtShGet).discover(ctx({ apexes: ['example.com'] }))),
    ).rejects.toThrow(/only crt\.sh/);
    expect(crtShGet).toHaveBeenCalledTimes(1);
  });

  it('refuses a private resolved IP for crt.sh before any CT HTTPS connect', async () => {
    const crtShGet = vi.fn<CrtShGet>(async () => jsonResult([]));
    const dns = mockDns({
      resolve4: async (h) => (h === CRT_SH_HOST ? ['10.0.0.1'] : []),
    });
    await expect(
      collect(connector(crtShGet, dns).discover(ctx({ apexes: ['example.com'] }))),
    ).rejects.toThrow(/non-public resolved IP/);
    expect(crtShGet).not.toHaveBeenCalled();
  });

  it('fails when the CT body hits the size cap', async () => {
    const crtShGet = vi.fn<CrtShGet>(async () =>
      jsonResult([], { truncated: true, body: 'x'.repeat(100) }),
    );
    await expect(
      collect(connector(crtShGet).discover(ctx({ apexes: ['example.com'] }))),
    ).rejects.toThrow(/truncated at response size cap/);
  });

  it('fails when CT paging is truncated at the page cap', async () => {
    const crtShGet = vi.fn<CrtShGet>(async () =>
      jsonResult([], {
        headers: { link: '<https://crt.sh/?q=%25.example.com&output=json&id=2>; rel="next"' },
      }),
    );
    await expect(
      collect(connector(crtShGet).discover(ctx({ apexes: ['example.com'] }))),
    ).rejects.toThrow(/truncated at page cap/);
    expect(crtShGet).toHaveBeenCalledTimes(DNS_CT_MAX_PAGES);
  });

  it('fails when more than 200 under-apex names would be minted', async () => {
    const rows = Array.from({ length: DNS_ENUM_MAX_NAMES }, (_, i) => ({
      name_value: `n${i}.example.com`,
    }));
    const crtShGet = vi.fn<CrtShGet>(async () => jsonResult(rows));
    await expect(
      collect(connector(crtShGet).discover(ctx({ apexes: ['example.com'] }))),
    ).rejects.toThrow(/truncated at 200 names/);
  });

  it('does not require a credentialRef and fails closed when one is unusable', async () => {
    const crtShGet = vi.fn<CrtShGet>(async () => jsonResult([]));
    const dns = mockDns({
      resolveNs: async () => [],
      resolve4: async (h) => (h === CRT_SH_HOST ? [CRT_SH_IP] : []),
    });
    const assets = await collect(
      connector(crtShGet, dns).discover(ctx({ apexes: ['example.com'] }, null)),
    );
    expect(assets.map((a) => a.externalKey)).toEqual(['dns:example.com']);

    await expect(
      collect(
        connector(crtShGet).discover(ctx({ apexes: ['example.com'] }, 'env:GITHUB_TOKEN')),
      ),
    ).rejects.toThrow(/cannot be used/);

    await expect(
      collect(
        connector(crtShGet).discover(ctx({ apexes: ['example.com'] }, 'env:DATABASE_URL')),
      ),
    ).rejects.toThrow(/not allowlisted/);
  });

  it('does not call SurfaceProbe.probe', async () => {
    const crtShGet = vi.fn<CrtShGet>(async () => jsonResult([]));
    await collect(connector(crtShGet).discover(ctx({ apexes: ['example.com'] })));
    expect(crtShGet.mock.calls.every((c) => c[0].connectIp === CRT_SH_IP)).toBe(true);
  });
});

describe('truncation does not archiveStale', () => {
  it('leaves archiveStale uncalled when CT paging is truncated', async () => {
    const crtShGet = vi.fn<CrtShGet>(async () =>
      jsonResult([], {
        headers: { link: '<https://crt.sh/?q=%25.example.com&output=json&id=2>; rel="next"' },
      }),
    );
    const registry = new ConnectorRegistry();
    registry.register(connector(crtShGet));
    const upsert = vi.fn();
    const archiveStale = vi.fn(async () => ({ count: 0 }));
    const prisma = {
      withOrg: vi.fn(async (_orgId: string, fn: (tx: { integration: { update: ReturnType<typeof vi.fn> } }) => unknown) =>
        fn({ integration: { update: vi.fn() } }),
      ),
    };
    const scheduler = new DiscoverySchedulerService(
      prisma as unknown as PrismaService,
      registry,
      { upsert, archiveStale } as never,
    );

    const result = await scheduler.syncIntegration({
      id: 'int-1',
      orgId: 'org-1',
      provider: 'dns_enum',
      config: { apexes: ['example.com'] },
      credentialRef: null,
      lastSyncAt: null,
    });

    expect(result.error).toMatch(/truncated at page cap/);
    expect(result.archived).toBe(0);
    expect(archiveStale).not.toHaveBeenCalled();
    expect(upsert).not.toHaveBeenCalled();
  });
});

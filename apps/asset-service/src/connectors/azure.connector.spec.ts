import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AZURE_MAX_PAGES,
  AZURE_PER_PAGE,
  AzureConnector,
  nextLink,
  nsgToAsset,
  parseNsgs,
  parseVirtualMachines,
  storageAccountToAsset,
  vmToAsset,
  type AzureVirtualMachine,
} from './azure.connector';
import type { DiscoveryContext } from './connector.registry';

const SUB = '11111111-1111-1111-1111-111111111111';
const TENANT = '22222222-2222-2222-2222-222222222222';
const CLIENT = '33333333-3333-3333-3333-333333333333';
const RG = 'rg-prod';

const ctx = (
  config: Record<string, unknown> = { subscriptionId: SUB },
  credentialRef: string | null = 'env:AZURE_CLIENT_ID',
): DiscoveryContext => ({
  orgId: 'org-1',
  integrationId: 'int-1',
  config,
  credentialRef,
  since: null,
});

async function collect(iter: AsyncIterable<unknown>): Promise<unknown[]> {
  const out: unknown[] = [];
  for await (const item of iter) out.push(item);
  return out;
}

function vmResource(name: string, opts?: { publicIp?: boolean }): object {
  return {
    name,
    id: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachines/${name}`,
    location: 'eastus',
    properties: {
      provisioningState: 'Succeeded',
      networkProfile: {
        networkInterfaces: [
          {
            id: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/networkInterfaces/${name}-nic`,
            ...(opts?.publicIp
              ? {
                  properties: {
                    ipConfigurations: [
                      {
                        properties: {
                          publicIPAddress: {
                            id: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/publicIPAddresses/${name}-pip`,
                          },
                        },
                      },
                    ],
                  },
                }
              : {}),
          },
        ],
      },
    },
  };
}

function vmBody(names: string[], next?: string): string {
  return JSON.stringify({
    value: names.map((name) => vmResource(name)),
    ...(next ? { nextLink: next } : {}),
  });
}

function emptyList(): string {
  return JSON.stringify({ value: [] });
}

function stubAzure(opts: {
  vms?: string[][];
  storage?: string[];
  nextLinks?: Array<string | undefined>;
  status?: number;
  tokenStatus?: number;
}): ReturnType<typeof vi.fn> {
  let vmPage = 0;
  const fn = vi.fn(async (url: string | URL, _init?: RequestInit) => {
    const parsed = new URL(String(url));
    if (opts.tokenStatus && opts.tokenStatus !== 200 && parsed.hostname === 'login.microsoftonline.com') {
      return new Response('boom', { status: opts.tokenStatus });
    }
    if (parsed.hostname === 'login.microsoftonline.com') {
      return new Response(JSON.stringify({ access_token: 'eyJhbGciOiJSUzI1NiJ9.test' }), { status: 200 });
    }
    if (opts.status && opts.status !== 200) {
      return new Response('boom', { status: opts.status });
    }
    if (parsed.pathname.includes('/virtualMachines')) {
      const page = opts.vms?.[vmPage] ?? [];
      const more = opts.vms && vmPage < opts.vms.length - 1;
      const link =
        opts.nextLinks?.[vmPage] ??
        (more
          ? `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01&$skiptoken=page-${vmPage + 1}`
          : undefined);
      vmPage += 1;
      return new Response(vmBody(page, link), { status: 200 });
    }
    if (parsed.pathname.includes('/networkSecurityGroups')) {
      return new Response(emptyList(), { status: 200 });
    }
    if (parsed.pathname.includes('/publicIPAddresses')) {
      return new Response(emptyList(), { status: 200 });
    }
    if (parsed.pathname.includes('/storageAccounts')) {
      return new Response(
        JSON.stringify({
          value: (opts.storage ?? []).map((name) => ({
            name,
            id: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/${name}`,
            location: 'eastus',
          })),
        }),
        { status: 200 },
      );
    }
    return new Response('unexpected', { status: 500 });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function setAzureCreds(): void {
  process.env.AZURE_TENANT_ID = TENANT;
  process.env.AZURE_CLIENT_ID = CLIENT;
  process.env.AZURE_CLIENT_SECRET = 'super-secret';
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.AZURE_TENANT_ID;
  delete process.env.AZURE_CLIENT_ID;
  delete process.env.AZURE_CLIENT_SECRET;
});

describe('vmToAsset / storageAccountToAsset / nsgToAsset', () => {
  it('maps identity as cloud_resource', () => {
    const vm: AzureVirtualMachine = {
      name: 'web',
      resourceGroup: RG,
      location: 'eastus',
      hasPublicIp: true,
    };
    expect(vmToAsset(SUB, vm)).toMatchObject({
      kind: 'cloud_resource',
      externalKey: `azure:${SUB}:vm:${RG}:web`,
      name: 'web',
      source: 'azure',
      exposure: 'internet_facing',
    });
    expect(storageAccountToAsset(SUB, { name: 'logs', resourceGroup: RG })).toMatchObject({
      kind: 'cloud_resource',
      externalKey: `azure:${SUB}:sa:${RG}:logs`,
      source: 'azure',
      exposure: 'unknown',
    });
    expect(nsgToAsset(SUB, { name: 'web-nsg', resourceGroup: RG, internetOpen: false })).toMatchObject({
      kind: 'cloud_resource',
      externalKey: `azure:${SUB}:nsg:${RG}:web-nsg`,
      source: 'azure',
      exposure: 'internal',
    });
  });
});

describe('parseVirtualMachines / parseNsgs / nextLink', () => {
  it('reads VMs from the ARM list JSON and marks public-IP VMs internet_facing', () => {
    const json = {
      value: [vmResource('web-1', { publicIp: true }), vmResource('web-2')],
    };
    const parsed = parseVirtualMachines(json);
    expect(parsed.map((v) => v.name)).toEqual(['web-1', 'web-2']);
    expect(parsed[0]?.hasPublicIp).toBe(true);
    expect(parsed[1]?.hasPublicIp).toBe(false);
  });

  it('marks NSGs internet-open only for inbound Allow from * / Internet / 0.0.0.0/0', () => {
    const json = {
      value: [
        {
          name: 'open',
          id: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/networkSecurityGroups/open`,
          location: 'eastus',
          properties: {
            securityRules: [
              {
                name: 'allow-ssh',
                properties: {
                  direction: 'Inbound',
                  access: 'Allow',
                  sourceAddressPrefix: '*',
                },
              },
            ],
          },
        },
        {
          name: 'egress-only',
          id: `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/networkSecurityGroups/egress-only`,
          location: 'eastus',
          properties: {
            securityRules: [
              {
                name: 'allow-out',
                properties: {
                  direction: 'Outbound',
                  access: 'Allow',
                  sourceAddressPrefix: '*',
                  destinationAddressPrefix: 'Internet',
                },
              },
            ],
          },
        },
      ],
    };
    const parsed = parseNsgs(json);
    expect(parsed.find((n) => n.name === 'open')?.internetOpen).toBe(true);
    expect(parsed.find((n) => n.name === 'egress-only')?.internetOpen).toBe(false);
  });

  it('treats missing nextLink as complete even when the page is AZURE_PER_PAGE long', () => {
    expect(nextLink({ value: Array.from({ length: AZURE_PER_PAGE }, () => ({})) })).toBeUndefined();
    expect(nextLink({ value: [], nextLink: `https://management.azure.com/subscriptions/${SUB}/x` })).toBe(
      `https://management.azure.com/subscriptions/${SUB}/x`,
    );
  });
});

describe('AzureConnector.discover', () => {
  it('inventories ARM resources as cloud_resource against allowlisted Azure hosts', async () => {
    setAzureCreds();
    const fetchFn = stubAzure({ vms: [['web-1']], storage: ['acmelogs'] });
    const assets = (await collect(new AzureConnector().discover(ctx()))) as Array<{
      kind: string;
      source: string;
      externalKey: string;
    }>;
    expect(assets.every((a) => a.kind === 'cloud_resource')).toBe(true);
    expect(assets.every((a) => a.source === 'azure')).toBe(true);
    expect(assets.map((a) => a.externalKey)).toEqual(
      expect.arrayContaining([
        `azure:${SUB}:vm:${RG}:web-1`,
        `azure:${SUB}:sa:${RG}:acmelogs`,
      ]),
    );
    for (const [url] of fetchFn.mock.calls) {
      const host = new URL(String(url)).hostname;
      expect(['login.microsoftonline.com', 'management.azure.com']).toContain(host);
      expect(host).not.toContain('evil');
    }
    expect(String(fetchFn.mock.calls[0][0])).toBe(
      `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`,
    );
    expect(
      fetchFn.mock.calls.some(([url]) =>
        String(url).startsWith(
          `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.Compute/virtualMachines`,
        ),
      ),
    ).toBe(true);
    expect(
      fetchFn.mock.calls.some(([url]) =>
        String(url).includes(
          `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.Storage/storageAccounts`,
        ),
      ),
    ).toBe(true);
  });

  it('uses the authenticated ARM URL we built for overlapping pages, never a tenant host', async () => {
    setAzureCreds();
    const page2 =
      `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01&$skiptoken=abc`;
    const fetchFn = stubAzure({
      vms: [
        Array.from({ length: 2 }, (_, i) => `web-a-${i}`),
        Array.from({ length: 2 }, (_, i) => `web-b-${i}`),
      ],
      nextLinks: [page2, undefined],
    });
    const assets = (await collect(
      new AzureConnector().discover(ctx({ subscriptionId: SUB, resourceTypes: ['virtual_machine'] })),
    )) as Array<{ externalKey: string }>;
    expect(assets).toHaveLength(4);
    const armCalls = fetchFn.mock.calls
      .map(([url]) => String(url))
      .filter((url) => url.includes('/virtualMachines'));
    expect(armCalls[0]).toBe(
      `https://management.azure.com/subscriptions/${SUB}/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01`,
    );
    expect(armCalls[1]).toBe(page2);
    for (const [url] of fetchFn.mock.calls) {
      expect(new URL(String(url)).hostname).not.toContain('evil');
      expect(['login.microsoftonline.com', 'management.azure.com']).toContain(new URL(String(url)).hostname);
    }
  });

  it('refuses an off-allowlist nextLink and never sends the bearer there', async () => {
    setAzureCreds();
    const fetchFn = stubAzure({
      vms: [['web-1']],
      nextLinks: ['https://evil.example/arm?$skiptoken=exfil'],
    });
    await expect(
      collect(new AzureConnector().discover(ctx({ subscriptionId: SUB, resourceTypes: ['virtual_machine'] }))),
    ).rejects.toThrow(/only management\.azure\.com/);
    for (const [url] of fetchFn.mock.calls) {
      expect(String(url)).not.toContain('evil.example');
    }
  });

  it('fails closed when AZURE_* credentials are missing', async () => {
    const fetchFn = stubAzure({ vms: [['web-1']] });
    await expect(collect(new AzureConnector().discover(ctx()))).rejects.toThrow(/cannot be used/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when credentialRef is unset — no unauthenticated listing', async () => {
    setAzureCreds();
    const fetchFn = stubAzure({ vms: [['web-1']] });
    await expect(collect(new AzureConnector().discover(ctx({ subscriptionId: SUB }, null)))).rejects.toThrow(
      /env:AZURE_\*/,
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses env:GITHUB_TOKEN even when Azure secrets are present', async () => {
    setAzureCreds();
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchFn = stubAzure({ vms: [['web-1']] });
    await expect(
      collect(new AzureConnector().discover(ctx({ subscriptionId: SUB }, 'env:GITHUB_TOKEN'))),
    ).rejects.toThrow(/env:AZURE_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
    delete process.env.GITHUB_TOKEN;
  });

  it('refuses env:AWS_* even when Azure secrets are present', async () => {
    setAzureCreds();
    process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
    const fetchFn = stubAzure({ vms: [['web-1']] });
    await expect(
      collect(new AzureConnector().discover(ctx({ subscriptionId: SUB }, 'env:AWS_ACCESS_KEY_ID'))),
    ).rejects.toThrow(/env:AZURE_\*/);
    expect(fetchFn).not.toHaveBeenCalled();
    delete process.env.AWS_ACCESS_KEY_ID;
  });

  it('refuses a tenant-writable endpoint and never sends keys there', async () => {
    setAzureCreds();
    const fetchFn = stubAzure({ vms: [['web-1']] });
    await expect(
      collect(
        new AzureConnector().discover(
          ctx({
            subscriptionId: SUB,
            endpoint: 'https://evil.example',
            apiUrl: 'https://evil.example/arm',
            host: 'evil.example',
            loginUrl: 'https://evil.example/login',
            tokenUrl: 'https://evil.example/token',
            armEndpoint: 'https://evil.example/arm',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable Azure endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('does not take a tenant-supplied host even when mixed with a valid subscriptionId', async () => {
    setAzureCreds();
    const fetchFn = stubAzure({ vms: [['web-1']], storage: [] });
    await expect(
      collect(
        new AzureConnector().discover(
          ctx({
            subscriptionId: SUB,
            authority: 'https://login.microsoftonline.com.evil.example',
            cloud: 'AzureChinaCloud',
            environment: 'AzureUSGovernment',
            resourceManagerUrl: 'https://management.azure.com.evil.example',
          }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable Azure endpoint/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('requires a valid Azure subscription identifier', async () => {
    setAzureCreds();
    await expect(
      collect(new AzureConnector().discover(ctx({ subscriptionId: 'acme-prod.evil.example' }))),
    ).rejects.toThrow(/subscriptionId|subscription identifier|tenant-writable/);
  });

  it('succeeds on a last page of AZURE_PER_PAGE with no nextLink', async () => {
    setAzureCreds();
    const names = Array.from({ length: AZURE_PER_PAGE }, (_, i) => `web-full-${i}`);
    const fetchFn = stubAzure({ vms: [names], storage: [] });
    const assets = (await collect(
      new AzureConnector().discover(ctx({ subscriptionId: SUB, resourceTypes: ['virtual_machine'] })),
    )) as Array<{ externalKey: string }>;
    expect(assets).toHaveLength(AZURE_PER_PAGE);
    expect(assets.map((a) => a.externalKey)).toEqual(
      names.map((name) => `azure:${SUB}:vm:${RG}:${name}`),
    );
    const vmCalls = fetchFn.mock.calls.filter(([url]) => String(url).includes('/virtualMachines'));
    expect(vmCalls).toHaveLength(1);
  });

  it('fails when a VM listing is truncated at the page cap', async () => {
    setAzureCreds();
    const pages = Array.from({ length: AZURE_MAX_PAGES + 1 }, (_, p) =>
      Array.from({ length: AZURE_PER_PAGE }, (_, i) => `web-${p}-${i}`),
    );
    const fetchFn = stubAzure({ vms: pages, storage: [] });
    await expect(
      collect(
        new AzureConnector().discover(ctx({ subscriptionId: SUB, resourceTypes: ['virtual_machine'] })),
      ),
    ).rejects.toThrow(/truncated/);
    const vmCalls = fetchFn.mock.calls.filter(([url]) => String(url).includes('/virtualMachines'));
    expect(vmCalls).toHaveLength(AZURE_MAX_PAGES);
  });

  it('surfaces API failures so the scheduler records them on the integration', async () => {
    setAzureCreds();
    stubAzure({ status: 403 });
    await expect(collect(new AzureConnector().discover(ctx()))).rejects.toThrow(/403/);
  });

  it('rejects an unsupported credential scheme loudly', async () => {
    await expect(
      collect(new AzureConnector().discover(ctx({ subscriptionId: SUB }, 'vault:azure'))),
    ).rejects.toThrow(/Unsupported credentialRef scheme/);
  });

  it('refuses a non-allowlisted env credentialRef without reading the secret', async () => {
    process.env.DATABASE_URL = 'postgres://should-not-leak';
    await expect(
      collect(new AzureConnector().discover(ctx({ subscriptionId: SUB }, 'env:DATABASE_URL'))),
    ).rejects.toThrow(/not allowlisted/);
  });
});

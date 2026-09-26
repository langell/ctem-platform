import { generateKeyPairSync } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CircuitBreakerConfigError,
  CircuitOpenError,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  InternalHttpPolicy,
  type CircuitBreakerConfig,
} from '@ctem/resilience';
import { AzureConnector } from './azure.connector';
import { BitbucketConnector } from './bitbucket.connector';
import { exchangeAzureAccessToken } from './azure.token';
import type { DiscoveryContext } from './connector.registry';
import { DnsEnumConnector } from './dns.connector';
import type { CrtShGet, CrtShHttpResult } from './dns.egress';
import { exchangeGcpAccessToken } from './gcp.jwt';
import { GcpConnector } from './gcp.connector';
import { GitHubConnector } from './github.connector';
import { GitLabConnector } from './gitlab.connector';
import {
  EGRESS_AZURE_API,
  EGRESS_BITBUCKET_API,
  EGRESS_DNS_CT,
  EGRESS_GCP_API,
  EGRESS_GITHUB_API,
  EGRESS_GITLAB_API,
  EGRESS_K8S_CONTROLPLANE,
  resetInventoryEgressPolicy,
  useInventoryEgressPolicy,
} from './inventory-egress';
import { KubernetesConnector } from './kubernetes.connector';

const TENANT = '22222222-2222-2222-2222-222222222222';
const CLIENT = '33333333-3333-3333-3333-333333333333';
const SUB = '11111111-1111-1111-1111-111111111111';
const PROJECT = 'acme-prod';
const CRT_SH_IP = '93.184.216.34';

const gcpPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

const azureCreds = {
  tenantId: TENANT,
  clientId: CLIENT,
  clientSecret: 'super-secret',
};
const gcpCreds = {
  clientEmail: 'ctem-discovery@acme-prod.iam.gserviceaccount.com',
  privateKey: gcpPem,
};

function ctx(config: Record<string, unknown>, credentialRef: string | null = null): DiscoveryContext {
  return { orgId: 'org-1', integrationId: 'int-1', config, credentialRef, since: null };
}

async function collect(iter: AsyncIterable<unknown>): Promise<unknown[]> {
  const out: unknown[] = [];
  for await (const item of iter) out.push(item);
  return out;
}

function fastPolicy(overrides: Partial<CircuitBreakerConfig> = {}): InternalHttpPolicy {
  return new InternalHttpPolicy(
    {
      ...DEFAULT_CIRCUIT_BREAKER_CONFIG,
      failureThreshold: 5,
      maxAttempts: 3,
      baseDelayMs: 1,
      timeoutMs: 1_000,
      ...overrides,
    },
    { sleep: async () => undefined, random: () => 0 },
  );
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function setAzureEnv(): void {
  process.env.AZURE_TENANT_ID = TENANT;
  process.env.AZURE_CLIENT_ID = CLIENT;
  process.env.AZURE_CLIENT_SECRET = 'super-secret';
}

function setGcpEnv(): void {
  process.env.GCP_CLIENT_EMAIL = gcpCreds.clientEmail;
  process.env.GCP_PRIVATE_KEY = gcpPem;
}

function setAwsEnv(): void {
  process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
  process.env.AWS_SECRET_ACCESS_KEY = 'secret';
}

function clearCloudEnv(): void {
  for (const key of [
    'AZURE_TENANT_ID',
    'AZURE_CLIENT_ID',
    'AZURE_CLIENT_SECRET',
    'GCP_CLIENT_EMAIL',
    'GCP_PRIVATE_KEY',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'BITBUCKET_TOKEN',
  ]) {
    delete process.env[key];
  }
}

beforeEach(() => {
  useInventoryEgressPolicy(fastPolicy());
});

afterEach(() => {
  resetInventoryEgressPolicy();
  vi.unstubAllGlobals();
  clearCloudEnv();
});

describe('inventory egress circuit breaker', () => {
  it('fails one family closed without fetch once open, and leaves other families up', async () => {
    useInventoryEgressPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 1 }));
    const fetchFn = vi.fn(async (url: string) => {
      const host = new URL(String(url)).hostname;
      if (host === 'gitlab.com') return json([]);
      return new Response('down', { status: 503 });
    });
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).rejects.toThrow(/503/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    fetchFn.mockClear();

    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).rejects.toMatchObject({ name: 'CircuitOpenError', circuit: EGRESS_GITHUB_API });
    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).rejects.toBeInstanceOf(CircuitOpenError);
    expect(fetchFn).not.toHaveBeenCalled();

    await expect(
      collect(new GitLabConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).resolves.toEqual([]);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(new URL(String(fetchFn.mock.calls[0]![0])).hostname).toBe('gitlab.com');
    expect(EGRESS_GITLAB_API).not.toBe(EGRESS_GITHUB_API);
  });

  it('opens egress:bitbucket-api without fetch once open, and leaves GitHub up', async () => {
    useInventoryEgressPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 1 }));
    process.env.BITBUCKET_TOKEN = 'bb-token';
    const fetchFn = vi.fn(async (url: string) => {
      const host = new URL(String(url)).hostname;
      if (host === 'api.github.com') return json([]);
      return new Response('down', { status: 503 });
    });
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      collect(
        new BitbucketConnector().discover(
          ctx({ workspace: 'langell' }, 'env:BITBUCKET_TOKEN'),
        ),
      ),
    ).rejects.toThrow(/503/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(new URL(String(fetchFn.mock.calls[0]![0])).hostname).toBe('api.bitbucket.org');
    fetchFn.mockClear();

    await expect(
      collect(
        new BitbucketConnector().discover(
          ctx({ workspace: 'langell' }, 'env:BITBUCKET_TOKEN'),
        ),
      ),
    ).rejects.toMatchObject({ name: 'CircuitOpenError', circuit: EGRESS_BITBUCKET_API });
    expect(fetchFn).not.toHaveBeenCalled();

    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).resolves.toEqual([]);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(new URL(String(fetchFn.mock.calls[0]![0])).hostname).toBe('api.github.com');
    expect(EGRESS_BITBUCKET_API).not.toBe(EGRESS_GITHUB_API);
  });

  it('completes a retryable 503 then success within the attempt budget', async () => {
    useInventoryEgressPolicy(fastPolicy({ maxAttempts: 3, failureThreshold: 5 }));
    let calls = 0;
    const fetchFn = vi.fn(async () => {
      calls += 1;
      if (calls === 1) return new Response('unavailable', { status: 503 });
      return json([]);
    });
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).resolves.toEqual([]);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('fails the sync closed when the retry budget is exhausted', async () => {
    useInventoryEgressPolicy(fastPolicy({ maxAttempts: 3, failureThreshold: 5 }));
    const fetchFn = vi.fn(async () => new Response('down', { status: 503 }));
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).rejects.toThrow(/503/);
    expect(fetchFn).toHaveBeenCalledTimes(3);
  });

  it('does not retry 4xx or open the circuit', async () => {
    useInventoryEgressPolicy(fastPolicy({ maxAttempts: 3, failureThreshold: 1 }));
    const fetchFn = vi.fn(async () => new Response('missing', { status: 404 }));
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).rejects.toThrow(/404/);
    expect(fetchFn).toHaveBeenCalledTimes(1);

    fetchFn.mockResolvedValue(json([]));
    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).resolves.toEqual([]);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it('keeps allowlist refusal ahead of the policy and does not open the circuit', async () => {
    useInventoryEgressPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 1 }));
    const fetchFn = vi.fn(async () => json([]));
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      collect(
        new GitLabConnector().discover(
          ctx({ owner: 'langell', ownerType: 'user', baseUrl: 'https://user:pass@gitlab.example.com' }),
        ),
      ),
    ).rejects.toThrow(/userinfo/);
    await expect(
      collect(
        new GitLabConnector().discover(
          ctx({ owner: 'langell', ownerType: 'user', host: 'evil.example' }),
        ),
      ),
    ).rejects.toThrow(/tenant-writable GitLab host/);
    expect(fetchFn).not.toHaveBeenCalled();

    await expect(
      collect(new GitLabConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).resolves.toEqual([]);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('shares egress:azure-api between the token helper and Azure API traffic', async () => {
    useInventoryEgressPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 1 }));
    setAzureEnv();
    setGcpEnv();
    const fetchFn = vi.fn(async (url: string) => {
      const host = new URL(String(url)).hostname;
      if (host === 'login.microsoftonline.com') return json({ access_token: 'azure-tok' });
      if (host === 'oauth2.googleapis.com') return json({ access_token: 'gcp-tok' });
      return new Response('down', { status: 503 });
    });
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      collect(
        new AzureConnector().discover(
          ctx({ subscriptionId: SUB, resourceTypes: ['virtual_machine'] }, 'env:AZURE_CLIENT_ID'),
        ),
      ),
    ).rejects.toThrow(/503/);
    expect(fetchFn.mock.calls.map(([url]) => new URL(String(url)).hostname)).toEqual([
      'login.microsoftonline.com',
      'management.azure.com',
    ]);
    fetchFn.mockClear();

    await expect(exchangeAzureAccessToken(azureCreds)).rejects.toMatchObject({
      name: 'CircuitOpenError',
      circuit: EGRESS_AZURE_API,
    });
    await expect(
      collect(
        new KubernetesConnector().discover(
          ctx({ cloud: 'azure', subscriptionId: SUB }, 'env:AZURE_CLIENT_ID'),
        ),
      ),
    ).rejects.toBeInstanceOf(CircuitOpenError);
    expect(fetchFn).not.toHaveBeenCalled();

    await expect(exchangeGcpAccessToken(gcpCreds)).resolves.toBe('gcp-tok');
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(new URL(String(fetchFn.mock.calls[0]![0])).hostname).toBe('oauth2.googleapis.com');
  });

  it('shares egress:gcp-api between the token helper and GCP API traffic', async () => {
    useInventoryEgressPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 1 }));
    setGcpEnv();
    const fetchFn = vi.fn(async (url: string) => {
      const host = new URL(String(url)).hostname;
      if (host === 'oauth2.googleapis.com') return json({ access_token: 'gcp-tok' });
      return new Response('down', { status: 503 });
    });
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      collect(
        new GcpConnector().discover(
          ctx({ projectId: PROJECT, resourceTypes: ['gce_instance'] }, 'env:GCP_CLIENT_EMAIL'),
        ),
      ),
    ).rejects.toThrow(/503/);
    expect(fetchFn.mock.calls.some(([url]) => String(url).includes('oauth2.googleapis.com'))).toBe(
      true,
    );
    expect(
      fetchFn.mock.calls.some(([url]) => new URL(String(url)).hostname.endsWith('googleapis.com')),
    ).toBe(true);
    fetchFn.mockClear();

    await expect(exchangeGcpAccessToken(gcpCreds)).rejects.toMatchObject({
      circuit: EGRESS_GCP_API,
    });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('does not count an Azure token scope refusal toward the circuit', async () => {
    useInventoryEgressPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 1 }));
    const fetchFn = vi.fn(async () => json({ access_token: 'azure-tok' }));
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      exchangeAzureAccessToken(azureCreds, 'https://evil.example/.default'),
    ).rejects.toThrow(/not allowlisted/);
    expect(fetchFn).not.toHaveBeenCalled();

    await expect(exchangeAzureAccessToken(azureCreds)).resolves.toBe('azure-tok');
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(new URL(String(fetchFn.mock.calls[0]![0])).hostname).toBe('login.microsoftonline.com');
  });

  it('opens egress:dns-ct without calling crt.sh again and without blocking GitHub', async () => {
    useInventoryEgressPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 1 }));
    const crtShGet = vi.fn<CrtShGet>(async () => ({
      statusCode: 503,
      headers: {},
      body: '',
      truncated: false,
    }));
    const connector = new DnsEnumConnector().useTestDeps({
      dns: {
        resolve4: async (host) => (host === 'crt.sh' ? [CRT_SH_IP] : ['8.8.8.8']),
        resolve6: async () => [],
        resolveCname: async () => [],
        resolveNs: async () => ['ns1.example.com'],
      },
      crtShGet,
    });

    await expect(collect(connector.discover(ctx({ apexes: ['example.com'] })))).rejects.toThrow(
      /HTTP 503/,
    );
    expect(crtShGet).toHaveBeenCalledTimes(1);
    crtShGet.mockClear();

    await expect(collect(connector.discover(ctx({ apexes: ['example.com'] })))).rejects.toMatchObject(
      { name: 'CircuitOpenError', circuit: EGRESS_DNS_CT },
    );
    expect(crtShGet).not.toHaveBeenCalled();

    const fetchFn = vi.fn(async () => json([]));
    vi.stubGlobal('fetch', fetchFn);
    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).resolves.toEqual([]);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('retries crt.sh 503 then success on the dns-ct circuit', async () => {
    useInventoryEgressPolicy(fastPolicy({ maxAttempts: 3, failureThreshold: 5 }));
    let calls = 0;
    const crtShGet = vi.fn<CrtShGet>(async () => {
      calls += 1;
      const result: CrtShHttpResult = {
        statusCode: calls === 1 ? 503 : 200,
        headers: {},
        body: '[]',
        truncated: false,
      };
      return result;
    });
    const connector = new DnsEnumConnector().useTestDeps({
      dns: {
        resolve4: async (host) => (host === 'crt.sh' || host === 'example.com' ? [CRT_SH_IP] : []),
        resolve6: async () => [],
        resolveCname: async () => [],
        resolveNs: async () => [],
      },
      crtShGet,
    });

    const assets = await collect(connector.discover(ctx({ apexes: ['example.com'] })));
    expect(assets.length).toBeGreaterThan(0);
    expect(crtShGet).toHaveBeenCalledTimes(2);
  });

  it('does not count a crt.sh allowlist refusal toward egress:dns-ct', async () => {
    useInventoryEgressPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 1 }));
    const crtShGet = vi.fn<CrtShGet>(async () => ({
      statusCode: 200,
      headers: {},
      body: '[]',
      truncated: false,
    }));
    const connector = new DnsEnumConnector().useTestDeps({
      dns: {
        resolve4: async () => [CRT_SH_IP],
        resolve6: async () => [],
        resolveCname: async () => [],
        resolveNs: async () => [],
      },
      crtShGet,
    });

    await expect(
      collect(connector.discover(ctx({ apexes: ['example.com'], ctUrl: 'https://evil.example/ct' }))),
    ).rejects.toThrow(/tenant-writable DNS endpoint/);
    expect(crtShGet).not.toHaveBeenCalled();

    await collect(connector.discover(ctx({ apexes: ['example.com'] })));
    expect(crtShGet).toHaveBeenCalledTimes(1);
  });

  it('opens the kubernetes control-plane circuit without blocking GitHub', async () => {
    useInventoryEgressPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 1 }));
    setAwsEnv();
    const fetchFn = vi.fn(async (url: string) => {
      const host = new URL(String(url)).hostname;
      if (host === 'api.github.com') return json([]);
      return new Response('down', { status: 503 });
    });
    vi.stubGlobal('fetch', fetchFn);

    await expect(
      collect(
        new KubernetesConnector().discover(
          ctx({ cloud: 'aws', region: 'us-east-1' }, 'env:AWS_ACCESS_KEY_ID'),
        ),
      ),
    ).rejects.toThrow(/503/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    fetchFn.mockClear();

    await expect(
      collect(
        new KubernetesConnector().discover(
          ctx({ cloud: 'aws', region: 'us-east-1' }, 'env:AWS_ACCESS_KEY_ID'),
        ),
      ),
    ).rejects.toMatchObject({ circuit: EGRESS_K8S_CONTROLPLANE });
    expect(fetchFn).not.toHaveBeenCalled();

    await expect(
      collect(new GitHubConnector().discover(ctx({ owner: 'langell', ownerType: 'user' }))),
    ).resolves.toEqual([]);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('fails closed on unknown CTEM_CB_* and does not add inventory-only knobs', () => {
    expect(() => resetInventoryEgressPolicy({ CTEM_CB_TIMEOUT_MS: 'nope' })).toThrow(
      CircuitBreakerConfigError,
    );
    expect(() => resetInventoryEgressPolicy({ CTEM_CB_INVENTORY_TIMEOUT_MS: '1000' })).toThrow(
      /allowlisted/,
    );
    expect(() => resetInventoryEgressPolicy({ CTEM_CB_ENABLED: 'false' })).toThrow(/fail closed/);
  });
});

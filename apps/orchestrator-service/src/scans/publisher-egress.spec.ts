import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CircuitBreakerConfigError,
  CircuitOpenError,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  InternalHttpPolicy,
  type CircuitBreakerConfig,
} from '@ctem/resilience';
import { allowlistedGithubApiUrl } from './github-checks.egress';
import { GithubChecksPublisher } from './github-checks.publisher';
import { GithubDeploymentsPublisher } from './github-deployments.publisher';
import { allowlistedGitLabApiUrl, GITLAB_COM } from './gitlab-statuses.egress';
import { GitlabCommitStatusPublisher } from './gitlab-statuses.publisher';
import { GitlabDeploymentsPublisher } from './gitlab-deployments.publisher';
import {
  EGRESS_GITHUB_API,
  EGRESS_GITLAB_API,
  resetPublisherEgressPolicy,
  usePublisherEgressPolicy,
} from './publisher-egress';

const SCAN_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_A = '4a6f9f4e-1111-4222-8333-444455556666';
const SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ASSET_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';

type PublishCase = {
  name: string;
  circuit: typeof EGRESS_GITHUB_API | typeof EGRESS_GITLAB_API;
  host: string;
  write: 'POST' | 'PUT';
  tokenEnv: 'GITHUB_TOKEN' | 'GITLAB_TOKEN';
  publish: () => Promise<void>;
  scanUpdate: ReturnType<typeof vi.fn>;
};

function fastPolicy(
  overrides: Partial<CircuitBreakerConfig> = {},
  log?: { warns: string[] },
): InternalHttpPolicy {
  return new InternalHttpPolicy(
    {
      ...DEFAULT_CIRCUIT_BREAKER_CONFIG,
      failureThreshold: 2,
      maxAttempts: 3,
      baseDelayMs: 1,
      timeoutMs: 1_000,
      ...overrides,
    },
    {
      sleep: async () => undefined,
      random: () => 0,
      log: log
        ? {
            info: () => undefined,
            warn: (_bindings, msg) => {
              log.warns.push(msg);
            },
          }
        : undefined,
    },
  );
}

function prismaFor(options: Record<string, unknown>, credentialRef: string) {
  const scan = {
    id: SCAN_ID,
    orgId: ORG_A,
    status: 'succeeded' as const,
    scannerType: 'sca',
    options,
    jobs: [
      {
        assetId: ASSET_A,
        findingCount: 0,
        asset: { integration: { credentialRef } },
      },
    ],
  };
  const tx = {
    scan: {
      findUnique: vi.fn(async () => scan),
      update: vi.fn(),
    },
    finding: { findMany: vi.fn(async () => []) },
    policy: { findMany: vi.fn(async () => []) },
    riskException: { findMany: vi.fn(async () => []) },
  };
  return {
    scan,
    tx,
    prisma: {
      withOrg: vi.fn(async (_orgId: string, fn: (client: typeof tx) => unknown) => fn(tx)),
    },
  };
}

function cases(): PublishCase[] {
  const githubChecks = prismaFor({ github: { repository: 'acme/api', sha: SHA } }, 'env:GITHUB_TOKEN');
  const githubDeployments = prismaFor(
    { github: { repository: 'acme/api', deploymentId: 42 } },
    'env:GITHUB_TOKEN',
  );
  const gitlabStatuses = prismaFor({ gitlab: { projectId: 'acme/api', sha: SHA } }, 'env:GITLAB_TOKEN');
  const gitlabDeployments = prismaFor(
    { gitlab: { projectId: 'acme/api', deploymentId: 42 } },
    'env:GITLAB_TOKEN',
  );
  return [
    {
      name: 'GitHub Checks',
      circuit: EGRESS_GITHUB_API,
      host: 'api.github.com',
      write: 'POST',
      tokenEnv: 'GITHUB_TOKEN',
      publish: () =>
        new GithubChecksPublisher(githubChecks.prisma as never).publishForCompletedScan(ORG_A, SCAN_ID),
      scanUpdate: githubChecks.tx.scan.update,
    },
    {
      name: 'GitHub Deployments',
      circuit: EGRESS_GITHUB_API,
      host: 'api.github.com',
      write: 'POST',
      tokenEnv: 'GITHUB_TOKEN',
      publish: () =>
        new GithubDeploymentsPublisher(githubDeployments.prisma as never).publishForCompletedScan(ORG_A, SCAN_ID),
      scanUpdate: githubDeployments.tx.scan.update,
    },
    {
      name: 'GitLab Commit Statuses',
      circuit: EGRESS_GITLAB_API,
      host: 'gitlab.com',
      write: 'POST',
      tokenEnv: 'GITLAB_TOKEN',
      publish: () =>
        new GitlabCommitStatusPublisher(gitlabStatuses.prisma as never).publishForCompletedScan(ORG_A, SCAN_ID),
      scanUpdate: gitlabStatuses.tx.scan.update,
    },
    {
      name: 'GitLab Deployments',
      circuit: EGRESS_GITLAB_API,
      host: 'gitlab.com',
      write: 'PUT',
      tokenEnv: 'GITLAB_TOKEN',
      publish: () =>
        new GitlabDeploymentsPublisher(gitlabDeployments.prisma as never).publishForCompletedScan(ORG_A, SCAN_ID),
      scanUpdate: gitlabDeployments.tx.scan.update,
    },
  ];
}

function installFetch(on: (method: string, url: string) => Response) {
  const fn = vi.fn(async (url: string, init?: { method?: string; headers?: Record<string, string> }) => {
    return on(init?.method ?? 'GET', String(url));
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function writes(fn: ReturnType<typeof installFetch>, method: string): unknown[][] {
  return fn.mock.calls.filter((call) => ((call[1] as { method?: string } | undefined)?.method ?? 'GET') === method);
}

beforeEach(() => {
  usePublisherEgressPolicy(fastPolicy());
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.GITHUB_TOKEN;
  delete process.env.GITLAB_TOKEN;
  resetPublisherEgressPolicy();
});

describe('publisher egress circuit breaker', () => {
  it('open circuit returns without throwing and does not POST/PUT', async () => {
    const warns: string[] = [];
    const policy = fastPolicy({ failureThreshold: 1, maxAttempts: 1 }, { warns });
    usePublisherEgressPolicy(policy);
    await policy.execute(EGRESS_GITHUB_API, async () => new Response('down', { status: 500 }));
    await policy.execute(EGRESS_GITLAB_API, async () => new Response('down', { status: 500 }));
    expect(warns).toContain('circuit opened');

    const publishers = cases();
    const fetchMock = installFetch(() => new Response('should not run', { status: 200 }));
    for (const publisher of publishers) {
      process.env[publisher.tokenEnv] = 'token-test';
      await expect(publisher.publish()).resolves.toBeUndefined();
    }
    expect(fetchMock).not.toHaveBeenCalled();
    expect(warns).toContain('circuit reject');
    for (const publisher of publishers) {
      expect(publisher.scanUpdate).not.toHaveBeenCalled();
    }
  });

  it('retries a 503 within budget and then publishes', async () => {
    usePublisherEgressPolicy(fastPolicy({ maxAttempts: 3 }));
    for (const publisher of cases()) {
      process.env[publisher.tokenEnv] = 'token-test';
      let writesSeen = 0;
      const fetchMock = installFetch((method, url) => {
        expect(new URL(url).hostname).toBe(publisher.host);
        if (method === 'GET') return new Response(JSON.stringify([]), { status: 200 });
        writesSeen += 1;
        if (writesSeen === 1) return new Response('unavailable', { status: 503 });
        return new Response(JSON.stringify({ id: 1, status: 'success' }), { status: 201 });
      });
      await expect(publisher.publish()).resolves.toBeUndefined();
      expect(writes(fetchMock, publisher.write)).toHaveLength(2);
      expect(writesSeen).toBeLessThanOrEqual(3);
      const sent = fetchMock.mock.calls.find(
        (call) => ((call[1] as { method?: string } | undefined)?.method ?? 'GET') === publisher.write,
      );
      const headers = (sent?.[1] as { headers?: Record<string, string> } | undefined)?.headers;
      expect(headers?.authorization).toMatch(/^Bearer /);
      expect(headers?.['user-agent']).toBe('ctem-platform');
    }
  });

  it('does not retry 4xx (including 429) and does not open the circuit', async () => {
    usePublisherEgressPolicy(fastPolicy({ failureThreshold: 1, maxAttempts: 3 }));
    for (const status of [422, 429]) {
      for (const publisher of cases()) {
        process.env[publisher.tokenEnv] = 'token-test';
        const fetchMock = installFetch((method) => {
          if (method === 'GET') return new Response(JSON.stringify([]), { status: 200 });
          return new Response('no', { status });
        });
        await expect(publisher.publish()).resolves.toBeUndefined();
        expect(writes(fetchMock, publisher.write)).toHaveLength(1);
        expect(publisher.scanUpdate).not.toHaveBeenCalled();
      }
    }

    const again = installFetch((method) => {
      if (method === 'GET') return new Response(JSON.stringify([]), { status: 200 });
      return new Response(JSON.stringify({ id: 1 }), { status: 201 });
    });
    process.env.GITHUB_TOKEN = 'token-test';
    await expect(cases()[0].publish()).resolves.toBeUndefined();
    expect(again).toHaveBeenCalled();
  });

  it('stops at the retry budget when every attempt is 503 and still soft-fails', async () => {
    usePublisherEgressPolicy(fastPolicy({ maxAttempts: 3, failureThreshold: 5 }));
    const publisher = cases()[0];
    process.env.GITHUB_TOKEN = 'token-test';
    const fetchMock = installFetch((method) => {
      if (method === 'GET') return new Response(JSON.stringify([]), { status: 200 });
      return new Response('unavailable', { status: 503 });
    });
    await expect(publisher.publish()).resolves.toBeUndefined();
    expect(writes(fetchMock, 'POST')).toHaveLength(3);
    expect(publisher.scanUpdate).not.toHaveBeenCalled();
  });

  it('keeps GitHub and GitLab circuits separate', async () => {
    const policy = fastPolicy({ failureThreshold: 1, maxAttempts: 1 });
    usePublisherEgressPolicy(policy);
    await policy.execute(EGRESS_GITHUB_API, async () => new Response('down', { status: 500 }));

    process.env.GITHUB_TOKEN = 'ghp_test';
    const githubFetch = installFetch(() => new Response('no', { status: 201 }));
    const publishers = cases();
    await expect(publishers[1].publish()).resolves.toBeUndefined();
    expect(githubFetch).not.toHaveBeenCalled();

    process.env.GITLAB_TOKEN = 'glpat-test';
    const gitlabFetch = installFetch((method) => {
      if (method === 'GET') return new Response(JSON.stringify([]), { status: 200 });
      return new Response(JSON.stringify({ id: 1 }), { status: 201 });
    });
    await expect(publishers[2].publish()).resolves.toBeUndefined();
    expect(writes(gitlabFetch, 'POST')).toHaveLength(1);
    for (const call of gitlabFetch.mock.calls) {
      expect(new URL(String(call[0])).hostname).toBe('gitlab.com');
    }
  });

  it('refuses non-allowlisted hosts before any fetch', () => {
    const fetchMock = installFetch(() => new Response('no', { status: 200 }));
    expect(() => allowlistedGithubApiUrl('https://github.example.com/api/v3/repos/acme/api/check-runs')).toThrow(
      /only api\.github\.com/,
    );
    expect(() => allowlistedGitLabApiUrl('https://evil.example/api/v4/projects/1/statuses/abc', GITLAB_COM)).toThrow(
      /only gitlab\.com is allowlisted/,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fails closed on invalid or unknown CTEM_CB_* and does not add publisher-only knobs', () => {
    expect(() => resetPublisherEgressPolicy({ CTEM_CB_TIMEOUT_MS: 'nope' })).toThrow(CircuitBreakerConfigError);
    expect(() => resetPublisherEgressPolicy({ CTEM_CB_PUBLISHER_TIMEOUT_MS: '1000' })).toThrow(/allowlisted/);
    expect(() => resetPublisherEgressPolicy({ CTEM_CB_ENABLED: 'false' })).toThrow(/fail closed/);
  });

  it('surfaces CircuitOpenError from the shared policy before the publisher swallows it', async () => {
    const policy = fastPolicy({ failureThreshold: 1, maxAttempts: 1 });
    usePublisherEgressPolicy(policy);
    await policy.execute(EGRESS_GITHUB_API, async () => new Response('down', { status: 500 }));
    await expect(
      policy.execute(EGRESS_GITHUB_API, async () => new Response('no', { status: 200 })),
    ).rejects.toBeInstanceOf(CircuitOpenError);
  });
});

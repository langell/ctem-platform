import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { BadRequestException } from '@nestjs/common';
import {
  CLIENT_CONCLUSION_KEYS,
  CreateScanRequest,
  concludeDeploy,
  concludeScan,
  findClientConclusionKeys,
} from '@ctem/contracts';
import { ZodBody } from '@ctem/service-kit';
import { GithubChecksPublisher } from './github-checks.publisher';
import { parseGithubChecksContext } from './github-checks.context';
import {
  GITHUB_API_HOST,
  allowlistedGithubApiUrl,
  deploymentStatusesUrl,
} from './github-deployments.egress';
import { parseGithubDeploymentsContext, parseGithubDeploymentId } from './github-deployments.context';
import {
  GithubDeploymentsPublisher,
  buildDeploymentStatusBody,
  publishDeploymentStatus,
} from './github-deployments.publisher';
import { checkConclusionFromScan, deploymentStatusFromDeploy } from './scan-conclusion.query';

const SCAN_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_A = '4a6f9f4e-1111-4222-8333-444455556666';
const SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DEPLOYMENT_ID = 4242;
const ASSET_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
const FINDING_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2';

const matchingFinding = {
  id: FINDING_A,
  severity: 'high',
  riskScore: 80,
  kev: false,
  epssScore: 0.2,
  fixAvailable: true,
  scannerType: 'sca',
  asset: { kind: 'repository', exposure: 'internal', criticality: 'tier2', tags: {} },
};

function githubOptions(over: Record<string, unknown> = {}) {
  return {
    github: {
      repository: 'acme/api',
      deploymentId: DEPLOYMENT_ID,
      ...over,
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.GITHUB_TOKEN;
  delete process.env.GITHUB_CHECKS_TOKEN;
  delete process.env.CTEM_PUBLIC_URL;
  delete process.env.GITHUB_API_URL;
});

describe('GitHub Deployment statuses allowlist — only api.github.com', () => {
  it('accepts https://api.github.com deployment-statuses URLs', () => {
    expect(allowlistedGithubApiUrl('https://api.github.com/repos/acme/api/deployments/4242/statuses')).toBe(
      'https://api.github.com/repos/acme/api/deployments/4242/statuses',
    );
    expect(deploymentStatusesUrl('acme', 'api', DEPLOYMENT_ID)).toBe(
      `https://${GITHUB_API_HOST}/repos/acme/api/deployments/${DEPLOYMENT_ID}/statuses`,
    );
  });

  it('refuses GitHub Enterprise, github.com, suffix-confusion, http, userinfo, and ports', () => {
    expect(() =>
      allowlistedGithubApiUrl('https://github.example.com/api/v3/repos/acme/api/deployments/1/statuses'),
    ).toThrow(/only api\.github\.com/);
    expect(() => allowlistedGithubApiUrl('https://ghe.internal/api/v3/deployments/1/statuses')).toThrow(
      /only api\.github\.com/,
    );
    expect(() => allowlistedGithubApiUrl('https://github.com/acme/api')).toThrow(/only api\.github\.com/);
    expect(() =>
      allowlistedGithubApiUrl('https://api.github.com.evil.example/repos/acme/api/deployments/1/statuses'),
    ).toThrow(/only api\.github\.com/);
    expect(() => allowlistedGithubApiUrl('http://api.github.com/repos/acme/api/deployments/1/statuses')).toThrow(
      /non-https/,
    );
    expect(() =>
      allowlistedGithubApiUrl('https://user:pass@api.github.com/repos/acme/api/deployments/1/statuses'),
    ).toThrow(/userinfo/);
    expect(() => allowlistedGithubApiUrl('https://api.github.com:8443/repos/acme/api/deployments/1/statuses')).toThrow(
      /port/,
    );
  });

  it('does not follow GITHUB_API_URL or tenant baseUrl off api.github.com', () => {
    process.env.GITHUB_API_URL = 'https://github.example.com/api/v3';
    expect(deploymentStatusesUrl('acme', 'api', DEPLOYMENT_ID)).toBe(
      'https://api.github.com/repos/acme/api/deployments/4242/statuses',
    );
    const ctx = parseGithubDeploymentsContext(
      {
        github: {
          repository: 'acme/api',
          deploymentId: DEPLOYMENT_ID,
          baseUrl: 'https://github.example.com/api/v3',
          githubHost: 'github.example.com',
        },
      },
      SCAN_ID,
    );
    expect(ctx).toMatchObject({ owner: 'acme', repo: 'api', deploymentId: DEPLOYMENT_ID });
    expect(deploymentStatusesUrl(ctx!.owner, ctx!.repo, ctx!.deploymentId)).toBe(
      'https://api.github.com/repos/acme/api/deployments/4242/statuses',
    );
  });
});

describe('GitHub Deployments context — repository+deploymentId required', () => {
  it('parses options.github.repository owner/name and a positive deploymentId', () => {
    expect(parseGithubDeploymentsContext(githubOptions(), SCAN_ID)).toEqual({
      owner: 'acme',
      repo: 'api',
      deploymentId: DEPLOYMENT_ID,
    });
  });

  it('parses owner+repo, numeric string deploymentId, and top-level allowlisted keys', () => {
    expect(
      parseGithubDeploymentsContext(
        { github: { owner: 'acme', repo: 'api', deploymentId: '4242', environment: 'production' } },
        SCAN_ID,
      ),
    ).toMatchObject({ owner: 'acme', repo: 'api', deploymentId: 4242, environment: 'production' });
    expect(
      parseGithubDeploymentsContext({ repository: 'acme/api', deploymentId: DEPLOYMENT_ID }, SCAN_ID),
    ).toMatchObject({ owner: 'acme', repo: 'api', deploymentId: DEPLOYMENT_ID });
  });

  it('skips when deploymentId or repository is missing or not a github.com owner/name', () => {
    expect(parseGithubDeploymentsContext({ github: { repository: 'acme/api' } }, SCAN_ID)).toBeNull();
    expect(parseGithubDeploymentsContext({ github: { deploymentId: DEPLOYMENT_ID } }, SCAN_ID)).toBeNull();
    expect(parseGithubDeploymentsContext({ github: { repository: 'acme/api', deploymentId: 0 } }, SCAN_ID)).toBeNull();
    expect(
      parseGithubDeploymentsContext({ github: { repository: 'acme/api', deploymentId: -1 } }, SCAN_ID),
    ).toBeNull();
    expect(
      parseGithubDeploymentsContext({ github: { repository: 'acme/api', deploymentId: 1.5 } }, SCAN_ID),
    ).toBeNull();
    expect(
      parseGithubDeploymentsContext(
        { github: { repository: 'https://github.example.com/acme/api', deploymentId: DEPLOYMENT_ID } },
        SCAN_ID,
      ),
    ).toBeNull();
    expect(
      parseGithubDeploymentsContext(
        { github: { repository: 'github.com/acme/api', deploymentId: DEPLOYMENT_ID } },
        SCAN_ID,
      ),
    ).toBeNull();
    expect(parseGithubDeploymentsContext({}, SCAN_ID)).toBeNull();
  });

  it('refuses non-integer deploymentId forms', () => {
    expect(parseGithubDeploymentId('0')).toBeNull();
    expect(parseGithubDeploymentId('1e2')).toBeNull();
    expect(parseGithubDeploymentId('0x10')).toBeNull();
    expect(parseGithubDeploymentId('4242')).toBe(4242);
  });

  it('omits tenant-arbitrary logUrl hosts and only allows CTEM_PUBLIC_URL', () => {
    process.env.CTEM_PUBLIC_URL = 'https://ctem.example';
    expect(
      parseGithubDeploymentsContext(githubOptions({ logUrl: 'https://evil.example/v1/scans/' + SCAN_ID }), SCAN_ID)
        ?.logUrl,
    ).toBeUndefined();
    expect(
      parseGithubDeploymentsContext(githubOptions({ logUrl: `https://ctem.example/v1/scans/${SCAN_ID}` }), SCAN_ID)
        ?.logUrl,
    ).toBe(`https://ctem.example/v1/scans/${SCAN_ID}`);
  });

  it('omits environment values that look like a host URL', () => {
    expect(
      parseGithubDeploymentsContext(githubOptions({ environment: 'https://evil.example' }), SCAN_ID)?.environment,
    ).toBeUndefined();
    expect(
      parseGithubDeploymentsContext(githubOptions({ environment: 'staging' }), SCAN_ID)?.environment,
    ).toBe('staging');
  });
});

describe('client cannot write deploy/check conclusions — CLIENT_CONCLUSION_KEYS stay refused', () => {
  it('ZodBody 400s conclusion keys on create; nested options.github.deployConclusion is ignored', () => {
    const pipe = new ZodBody(CreateScanRequest);
    for (const key of CLIENT_CONCLUSION_KEYS) {
      expect(() => pipe.transform({ scannerType: 'sca', [key]: 'failed' }), key).toThrow(BadRequestException);
      expect(() => pipe.transform({ scannerType: 'sca', options: { [key]: 'blocked' } }), `options.${key}`).toThrow(
        BadRequestException,
      );
    }
    expect(findClientConclusionKeys({ scannerType: 'sca', deployConclusion: 'blocked' })).toEqual([
      'deployConclusion',
    ]);
    expect(
      CreateScanRequest.parse({
        scannerType: 'sca',
        options: { github: { repository: 'acme/api', deploymentId: DEPLOYMENT_ID, deployConclusion: 'blocked' } },
      }),
    ).toMatchObject({ scannerType: 'sca' });
    expect(
      CreateScanRequest.parse({
        scannerType: 'sca',
        options: { github: { repository: 'acme/api', deploymentId: DEPLOYMENT_ID } },
      }).options,
    ).toMatchObject({ github: { repository: 'acme/api', deploymentId: DEPLOYMENT_ID } });
  });
});

describe('concludeDeploy remains source of truth for GET and Deployment status mapping', () => {
  const finding = matchingFinding;
  const blockDeploy = {
    status: 'succeeded' as const,
    findings: [finding],
    policies: [{ priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['block_deploy'] }],
    expectedFindingCount: 1,
  };

  it('maps terminal blocked → failure and allowed → success; fail_build alone does not fail the status', () => {
    expect(concludeDeploy(blockDeploy)).toBe('blocked');
    expect(deploymentStatusFromDeploy(concludeDeploy(blockDeploy))).toBe('failure');
    expect(
      deploymentStatusFromDeploy(
        concludeDeploy({
          ...blockDeploy,
          policies: [{ priority: 10, condition: { kevOnly: true }, actions: ['block_deploy'] }],
        }),
      ),
    ).toBe('success');
    expect(
      deploymentStatusFromDeploy(
        concludeDeploy({
          ...blockDeploy,
          policies: [{ priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['fail_build'] }],
        }),
      ),
    ).toBe('success');
    expect(deploymentStatusFromDeploy('pending')).toBeNull();
    expect(
      buildDeploymentStatusBody(parseGithubDeploymentsContext(githubOptions(), SCAN_ID)!, SCAN_ID, 'failure').state,
    ).toBe('failure');
    expect(
      buildDeploymentStatusBody(parseGithubDeploymentsContext(githubOptions(), SCAN_ID)!, SCAN_ID, 'success').state,
    ).toBe('success');
    const body = buildDeploymentStatusBody(
      parseGithubDeploymentsContext(githubOptions(), SCAN_ID)!,
      SCAN_ID,
      'failure',
    );
    expect(body.description).toContain(SCAN_ID);
  });

  it('GET deployConclusion modules still do not call Deployments — statuses live in the publisher', () => {
    const deployCall = /deployments\/.+\/statuses|environments\/.+\/deployment-protection|required_reviewers/i;
    for (const rel of [
      'apps/orchestrator-service/src/scans/scans.controller.ts',
      'apps/orchestrator-service/src/scans/scan-conclusion.query.ts',
      'apps/api-gateway/src/routes/scans.controller.ts',
      'apps/risk-service/src/policy/policy-engine.service.ts',
      'libs/contracts/src/domain/scan-conclusion.ts',
    ]) {
      const src = readFileSync(resolve(rel), 'utf8');
      expect(src, rel).not.toMatch(deployCall);
    }
    const publisher = readFileSync(resolve('apps/orchestrator-service/src/scans/github-deployments.publisher.ts'), 'utf8');
    const egress = readFileSync(resolve('apps/orchestrator-service/src/scans/github-deployments.egress.ts'), 'utf8');
    const checksPublisher = readFileSync(resolve('apps/orchestrator-service/src/scans/github-checks.publisher.ts'), 'utf8');
    expect(egress).toMatch(/deployments\/\$\{/);
    expect(egress).toMatch(/api\.github\.com/);
    expect(publisher).toMatch(/deploymentStatusesUrl/);
    expect(publisher).not.toMatch(/check-runs|github\.example\.com|GITHUB_API_URL/);
    expect(egress).not.toMatch(/github\.example\.com/);
    expect(checksPublisher).not.toMatch(/deployments\//);
    expect(publisher).not.toMatch(/deployment-protection|required.reviewers|environment protection/i);
  });

  it('only fail_build still drives Checks — block_deploy does not flip the Check conclusion', () => {
    const failBuild = {
      status: 'succeeded' as const,
      findings: [finding],
      policies: [{ priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['fail_build'] }],
      expectedFindingCount: 1,
    };
    expect(checkConclusionFromScan(concludeScan(failBuild))).toBe('failure');
    expect(
      checkConclusionFromScan(
        concludeScan({
          ...failBuild,
          policies: [{ priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['block_deploy'] }],
        }),
      ),
    ).toBe('success');
    expect(parseGithubChecksContext({ github: { repository: 'acme/api', sha: SHA, deploymentId: 1 } }, SCAN_ID)).toMatchObject(
      { sha: SHA },
    );
  });
});

describe('GithubDeploymentsPublisher', () => {
  function prismaForScan(opts: { scan?: object | null; findings?: object[]; policies?: object[] } = {}) {
    const tx = {
      scan: { findUnique: vi.fn(async () => opts.scan ?? null) },
      finding: { findMany: vi.fn(async () => opts.findings ?? []) },
      policy: { findMany: vi.fn(async () => opts.policies ?? []) },
      riskException: { findMany: vi.fn(async () => []) },
    };
    const prisma = {
      withOrg: vi.fn(async (orgId: string, fn: (client: typeof tx) => unknown) => {
        expect(orgId).toBe(ORG_A);
        return fn(tx);
      }),
    };
    return { prisma, tx };
  }

  function scanRow(over: Record<string, unknown> = {}) {
    return {
      id: SCAN_ID,
      orgId: ORG_A,
      status: 'succeeded',
      scannerType: 'sca',
      options: githubOptions(),
      jobs: [
        {
          assetId: ASSET_A,
          findingCount: 1,
          asset: { integration: { credentialRef: 'env:GITHUB_TOKEN' } },
        },
      ],
      ...over,
    };
  }

  function stubFetch(opts: { list?: object[]; postStatus?: number; getStatus?: number } = {}) {
    const fn = vi.fn(async (url: string, init?: { method?: string; body?: string }) => {
      const parsed = new URL(String(url));
      expect(parsed.hostname).toBe('api.github.com');
      expect(parsed.protocol).toBe('https:');
      expect(parsed.pathname).toBe(`/repos/acme/api/deployments/${DEPLOYMENT_ID}/statuses`);
      const method = init?.method ?? 'GET';
      if (method === 'GET') {
        return new Response(JSON.stringify(opts.list ?? []), { status: opts.getStatus ?? 200 });
      }
      if (method === 'POST') {
        return new Response(JSON.stringify({ id: 99, state: 'failure' }), {
          status: opts.postStatus ?? 201,
        });
      }
      return new Response('unexpected', { status: 500 });
    });
    vi.stubGlobal('fetch', fn);
    return fn;
  }

  it('missing deploymentId skips the Deployment call — not a scan failure', async () => {
    const fetchMock = stubFetch();
    process.env.GITHUB_TOKEN = 'ghp_test';
    const { prisma } = prismaForScan({
      scan: scanRow({ options: { github: { repository: 'acme/api' } } }),
    });
    const publisher = new GithubDeploymentsPublisher(prisma as never);
    await expect(publisher.publishForCompletedScan(ORG_A, SCAN_ID)).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('pending concludeDeploy skips publish this slice', async () => {
    const fetchMock = stubFetch();
    process.env.GITHUB_TOKEN = 'ghp_test';
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [
          {
            assetId: ASSET_A,
            findingCount: 1,
            asset: { integration: { credentialRef: 'env:GITHUB_TOKEN' } },
          },
        ],
      }),
      findings: [],
      policies: [
        { enabled: true, priority: 10, condition: { severityAtLeast: 'high' }, actions: ['block_deploy'] },
      ],
    });
    await new GithubDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('block_deploy match → failure status on api.github.com', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [
        { enabled: true, priority: 10, condition: { severityAtLeast: 'high' }, actions: ['block_deploy'] },
      ],
    });
    await new GithubDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    expect(post).toBeTruthy();
    expect(String(post![0])).toBe(
      `https://api.github.com/repos/acme/api/deployments/${DEPLOYMENT_ID}/statuses`,
    );
    const body = JSON.parse(String((post![1] as { body: string }).body)) as {
      state: string;
      description: string;
    };
    expect(body.state).toBe('failure');
    expect(body.description).toContain(SCAN_ID);
  });

  it('matching fail_build does not fail the Deployment status — Deployments stay on concludeDeploy', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [
        { enabled: true, priority: 10, condition: { severityAtLeast: 'high' }, actions: ['fail_build'] },
      ],
    });
    await new GithubDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    const body = JSON.parse(String((post![1] as { body: string }).body)) as { state: string };
    expect(body.state).toBe('success');
  });

  it('no matching block_deploy → success status', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [{ enabled: true, priority: 10, condition: { kevOnly: true }, actions: ['notify'] }],
    });
    await new GithubDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    const body = JSON.parse(String((post![1] as { body: string }).body)) as { state: string };
    expect(body.state).toBe('success');
  });

  it('ignores client-supplied github.deployConclusion and still uses concludeDeploy', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        options: githubOptions({ deployConclusion: 'blocked' }),
        status: 'succeeded',
      }),
      findings: [matchingFinding],
      policies: [{ enabled: true, priority: 10, condition: { kevOnly: true }, actions: ['notify'] }],
    });
    await new GithubDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    const body = JSON.parse(String((post![1] as { body: string }).body)) as { state: string };
    expect(body.state).toBe('success');
  });

  it('skips a second POST when a status for the same scanId already exists', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchMock = stubFetch({
      list: [{ id: 77, description: `CTEM scan ${SCAN_ID} blocked`, state: 'failure' }],
    });
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [
          {
            assetId: ASSET_A,
            findingCount: 0,
            asset: { integration: { credentialRef: 'env:GITHUB_TOKEN' } },
          },
        ],
      }),
      findings: [],
      policies: [],
    });
    await new GithubDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const methods = fetchMock.mock.calls.map((call) => (call[1] as { method?: string })?.method ?? 'GET');
    expect(methods).toContain('GET');
    expect(methods).not.toContain('POST');
  });

  it('soft-fails a Deployment API error without throwing to the lifecycle caller', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    stubFetch({ postStatus: 502 });
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [
          {
            assetId: ASSET_A,
            findingCount: 0,
            asset: { integration: { credentialRef: 'env:GITHUB_TOKEN' } },
          },
        ],
      }),
      findings: [],
      policies: [],
    });
    await expect(
      new GithubDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID),
    ).resolves.toBeUndefined();
  });

  it('skips when GITHUB_* credentials are unusable — fail closed, no fetch', async () => {
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [{ assetId: ASSET_A, findingCount: 0, asset: { integration: { credentialRef: 'env:GITHUB_TOKEN' } } }],
      }),
    });
    await new GithubDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('Checks publisher still only hits check-runs when deploymentId is also present', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    const urls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: { method?: string }) => {
        urls.push(`${init?.method ?? 'GET'} ${url}`);
        const parsed = new URL(String(url));
        expect(parsed.hostname).toBe('api.github.com');
        if ((init?.method ?? 'GET') === 'GET' && parsed.pathname.includes('/commits/')) {
          return new Response(JSON.stringify({ check_runs: [] }), { status: 200 });
        }
        return new Response(JSON.stringify({ id: 1 }), { status: 201 });
      }),
    );
    const tx = {
      scan: {
        findUnique: vi.fn(async () => ({
          id: SCAN_ID,
          orgId: ORG_A,
          status: 'succeeded',
          scannerType: 'sca',
          options: { github: { repository: 'acme/api', sha: SHA, deploymentId: DEPLOYMENT_ID } },
          jobs: [
            {
              assetId: ASSET_A,
              findingCount: 0,
              asset: { integration: { credentialRef: 'env:GITHUB_TOKEN' } },
            },
          ],
        })),
      },
      finding: { findMany: vi.fn(async () => []) },
      policy: {
        findMany: vi.fn(async () => [
          { enabled: true, priority: 10, condition: { severityAtLeast: 'high' }, actions: ['block_deploy'] },
        ]),
      },
      riskException: { findMany: vi.fn(async () => []) },
    };
    const prisma = {
      withOrg: vi.fn(async (orgId: string, fn: (client: typeof tx) => unknown) => {
        expect(orgId).toBe(ORG_A);
        return fn(tx);
      }),
    };
    await new GithubChecksPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    expect(urls.some((u) => u.includes('/check-runs'))).toBe(true);
    expect(urls.some((u) => u.includes('/deployments/'))).toBe(false);
  });
});

describe('publishDeploymentStatus never leaves api.github.com', () => {
  it('POSTs only to https://api.github.com even if GITHUB_API_URL is enterprise', async () => {
    process.env.GITHUB_API_URL = 'https://github.example.com/api/v3';
    const urls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: { method?: string }) => {
        urls.push(String(url));
        if ((init?.method ?? 'GET') === 'GET') {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        return new Response(JSON.stringify({ id: 1 }), { status: 201 });
      }),
    );
    await publishDeploymentStatus({
      ctx: parseGithubDeploymentsContext(githubOptions(), SCAN_ID)!,
      scanId: SCAN_ID,
      state: 'success',
      token: 'ghp_test',
    });
    expect(urls.length).toBeGreaterThan(0);
    for (const url of urls) {
      expect(new URL(url).hostname).toBe('api.github.com');
      expect(url.startsWith('https://api.github.com/')).toBe(true);
      expect(url).toContain(`/deployments/${DEPLOYMENT_ID}/statuses`);
    }
  });
});

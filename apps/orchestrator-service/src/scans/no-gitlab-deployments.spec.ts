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
import { GitlabCommitStatusPublisher } from './gitlab-statuses.publisher';
import { parseGitlabStatusesContext } from './gitlab-statuses.context';
import {
  EXTRA_GITLAB_HOST_KEYS,
  GITLAB_COM,
  GITLAB_COM_API_URL,
  GITLAB_COM_HOST,
  allowlistedGitLabApiUrl,
  gitLabOriginFromScanJobs,
  gitlabDeploymentUrl,
  parseGitLabBaseUrl,
  refuseExtraGitLabHosts,
} from './gitlab-deployments.egress';
import {
  parseGitlabDeploymentId,
  parseGitlabDeploymentsContext,
} from './gitlab-deployments.context';
import {
  GitlabDeploymentsPublisher,
  buildDeploymentUpdateBody,
  publishGitlabDeployment,
} from './gitlab-deployments.publisher';
import {
  gitlabCommitStatusFromScan,
  gitlabDeploymentStatusFromDeploy,
} from './scan-conclusion.query';

const SCAN_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_A = '4a6f9f4e-1111-4222-8333-444455556666';
const SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DEPLOYMENT_ID = 4242;
const ASSET_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
const FINDING_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2';
const PROJECT = 'acme/api';
const SELF_HOSTED = 'https://gitlab.example.com';

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

function gitlabOptions(over: Record<string, unknown> = {}) {
  return {
    gitlab: {
      projectId: PROJECT,
      deploymentId: DEPLOYMENT_ID,
      ...over,
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.GITLAB_TOKEN;
  delete process.env.GITLAB_INT_TOKEN;
  delete process.env.CTEM_PUBLIC_URL;
});

describe('GitLab Deployments allowlist — gitlab.com or connector baseUrl', () => {
  it('accepts https://gitlab.com deployment URLs', () => {
    expect(
      allowlistedGitLabApiUrl(
        `${GITLAB_COM_API_URL}/projects/acme%2Fapi/deployments/${DEPLOYMENT_ID}`,
        GITLAB_COM,
      ),
    ).toContain('https://gitlab.com/api/v4/');
    expect(gitlabDeploymentUrl(GITLAB_COM, PROJECT, DEPLOYMENT_ID)).toBe(
      `https://${GITLAB_COM_HOST}/api/v4/projects/${encodeURIComponent(PROJECT)}/deployments/${DEPLOYMENT_ID}`,
    );
  });

  it('accepts a fixture self-hosted connector baseUrl and refuses any other host', () => {
    const origin = parseGitLabBaseUrl(SELF_HOSTED);
    expect(origin).toEqual({
      host: 'gitlab.example.com',
      origin: SELF_HOSTED,
      apiUrl: `${SELF_HOSTED}/api/v4`,
    });
    expect(gitlabDeploymentUrl(origin, PROJECT, DEPLOYMENT_ID)).toBe(
      `${SELF_HOSTED}/api/v4/projects/${encodeURIComponent(PROJECT)}/deployments/${DEPLOYMENT_ID}`,
    );
    expect(() =>
      allowlistedGitLabApiUrl('https://evil.example/api/v4/projects/1/deployments/1', origin),
    ).toThrow(/only gitlab\.example\.com is allowlisted/);
    expect(() =>
      allowlistedGitLabApiUrl(`${GITLAB_COM_API_URL}/projects/1/deployments/1`, origin),
    ).toThrow(/only gitlab\.example\.com is allowlisted/);
  });

  it('refuses http, userinfo, git@, ports, and suffix-confusion', () => {
    expect(() => parseGitLabBaseUrl('http://gitlab.example.com')).toThrow(/non-https/);
    expect(() => parseGitLabBaseUrl('git@gitlab.example.com:acme/api.git')).toThrow(/git@/);
    expect(() => parseGitLabBaseUrl('https://user:pass@gitlab.example.com')).toThrow(/userinfo/);
    expect(() =>
      allowlistedGitLabApiUrl(
        `https://user:pass@gitlab.com/api/v4/projects/1/deployments/${DEPLOYMENT_ID}`,
        GITLAB_COM,
      ),
    ).toThrow(/userinfo/);
    expect(() =>
      allowlistedGitLabApiUrl(
        `https://gitlab.com:8443/api/v4/projects/1/deployments/${DEPLOYMENT_ID}`,
        GITLAB_COM,
      ),
    ).toThrow(/port/);
    expect(() =>
      allowlistedGitLabApiUrl(
        `https://gitlab.com.evil.example/api/v4/projects/1/deployments/${DEPLOYMENT_ID}`,
        GITLAB_COM,
      ),
    ).toThrow(/only gitlab\.com is allowlisted/);
  });

  it('refuses a free-form scan host — origin is gitlab.com or connector baseUrl, never options.gitlab.apiUrl', () => {
    const ctx = parseGitlabDeploymentsContext(
      gitlabOptions({
        baseUrl: 'https://evil.example',
        apiUrl: 'https://evil.example/api/v4',
        host: 'evil.example',
        gitlabHost: 'evil.example',
      }),
    );
    expect(ctx).toMatchObject({ projectId: PROJECT, deploymentId: DEPLOYMENT_ID });
    expect(gitlabDeploymentUrl(GITLAB_COM, ctx!.projectId, ctx!.deploymentId)).toContain(
      'https://gitlab.com/api/v4/',
    );
    expect(gitlabDeploymentUrl(GITLAB_COM, ctx!.projectId, ctx!.deploymentId)).not.toContain(
      'evil.example',
    );

    expect(
      gitLabOriginFromScanJobs([
        {
          asset: {
            integration: {
              provider: 'gitlab',
              config: { owner: 'acme', baseUrl: SELF_HOSTED, apiUrl: 'https://evil.example' },
            },
          },
        },
      ]),
    ).toEqual(parseGitLabBaseUrl(SELF_HOSTED));

    expect(gitLabOriginFromScanJobs([])).toEqual(GITLAB_COM);
    expect(
      gitLabOriginFromScanJobs([
        { asset: { integration: { provider: 'github', config: { baseUrl: 'https://evil.example' } } } },
      ]),
    ).toEqual(GITLAB_COM);
  });
});

describe('GitLab Deployments context — projectId+deploymentId required', () => {
  it('parses options.gitlab.projectId path/with/namespace and a positive deploymentId', () => {
    expect(parseGitlabDeploymentsContext(gitlabOptions())).toEqual({
      projectId: PROJECT,
      deploymentId: DEPLOYMENT_ID,
    });
  });

  it('parses a numeric project id, numeric string deploymentId, and top-level allowlisted keys', () => {
    expect(parseGitlabDeploymentId(42)).toBe(42);
    expect(parseGitlabDeploymentId('4242')).toBe(4242);
    expect(
      parseGitlabDeploymentsContext({
        gitlab: { projectId: 99, deploymentId: '4242', environment: 'production' },
      }),
    ).toMatchObject({ projectId: '99', deploymentId: 4242, environment: 'production' });
    expect(
      parseGitlabDeploymentsContext({ projectId: PROJECT, deploymentId: DEPLOYMENT_ID }),
    ).toMatchObject({
      projectId: PROJECT,
      deploymentId: DEPLOYMENT_ID,
    });
  });

  it('skips when projectId or deploymentId is missing or not a GitLab project / deployment id', () => {
    expect(parseGitlabDeploymentsContext({ gitlab: { projectId: PROJECT } })).toBeNull();
    expect(parseGitlabDeploymentsContext({ gitlab: { deploymentId: DEPLOYMENT_ID } })).toBeNull();
    expect(parseGitlabDeploymentsContext({ gitlab: { projectId: PROJECT, deploymentId: 0 } })).toBeNull();
    expect(parseGitlabDeploymentsContext({ gitlab: { projectId: PROJECT, deploymentId: -1 } })).toBeNull();
    expect(parseGitlabDeploymentsContext({ gitlab: { projectId: PROJECT, deploymentId: 1.5 } })).toBeNull();
    expect(
      parseGitlabDeploymentsContext({
        gitlab: { projectId: 'https://gitlab.example.com/acme/api', deploymentId: DEPLOYMENT_ID },
      }),
    ).toBeNull();
    expect(
      parseGitlabDeploymentsContext({
        gitlab: { projectId: 'git@gitlab.com:acme/api.git', deploymentId: DEPLOYMENT_ID },
      }),
    ).toBeNull();
    expect(parseGitlabDeploymentsContext({})).toBeNull();
  });

  it('refuses non-integer deploymentId forms', () => {
    expect(parseGitlabDeploymentId('0')).toBeNull();
    expect(parseGitlabDeploymentId('1e2')).toBeNull();
    expect(parseGitlabDeploymentId('0x10')).toBeNull();
    expect(parseGitlabDeploymentId('4242')).toBe(4242);
  });

  it('does not require sha — Commit Status sha is optional for this publisher', () => {
    expect(parseGitlabDeploymentsContext(gitlabOptions())).toMatchObject({
      projectId: PROJECT,
      deploymentId: DEPLOYMENT_ID,
    });
    expect(parseGitlabDeploymentsContext(gitlabOptions({ sha: SHA }))).toMatchObject({
      projectId: PROJECT,
      deploymentId: DEPLOYMENT_ID,
    });
    expect(parseGitlabDeploymentsContext({ gitlab: { projectId: PROJECT, sha: SHA } })).toBeNull();
  });

  it('omits environment values that look like a host URL', () => {
    expect(parseGitlabDeploymentsContext(gitlabOptions({ environment: 'https://evil.example' }))?.environment).toBeUndefined();
    expect(parseGitlabDeploymentsContext(gitlabOptions({ environment: 'staging' }))?.environment).toBe(
      'staging',
    );
  });
});

describe('client cannot write deploy/check conclusions — CLIENT_CONCLUSION_KEYS stay refused', () => {
  it('ZodBody 400s conclusion keys on create; nested options.gitlab.deployConclusion is ignored', () => {
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
        options: {
          gitlab: { projectId: PROJECT, deploymentId: DEPLOYMENT_ID, deployConclusion: 'blocked' },
        },
      }),
    ).toMatchObject({ scannerType: 'sca' });
    expect(
      CreateScanRequest.parse({
        scannerType: 'sca',
        options: { gitlab: { projectId: PROJECT, deploymentId: DEPLOYMENT_ID } },
      }).options,
    ).toMatchObject({ gitlab: { projectId: PROJECT, deploymentId: DEPLOYMENT_ID } });
  });
});

describe('concludeDeploy remains source of truth for GET and GitLab Deployment mapping', () => {
  const finding = matchingFinding;
  const blockDeploy = {
    status: 'succeeded' as const,
    findings: [finding],
    policies: [{ priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['block_deploy'] }],
    expectedFindingCount: 1,
  };

  it('maps terminal blocked → failed and allowed → success; fail_build alone does not fail the status', () => {
    expect(concludeDeploy(blockDeploy)).toBe('blocked');
    expect(gitlabDeploymentStatusFromDeploy(concludeDeploy(blockDeploy))).toBe('failed');
    expect(
      gitlabDeploymentStatusFromDeploy(
        concludeDeploy({
          ...blockDeploy,
          policies: [{ priority: 10, condition: { kevOnly: true }, actions: ['block_deploy'] }],
        }),
      ),
    ).toBe('success');
    expect(
      gitlabDeploymentStatusFromDeploy(
        concludeDeploy({
          ...blockDeploy,
          policies: [{ priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['fail_build'] }],
        }),
      ),
    ).toBe('success');
    expect(gitlabDeploymentStatusFromDeploy('pending')).toBeNull();
    expect(buildDeploymentUpdateBody('failed').status).toBe('failed');
    expect(buildDeploymentUpdateBody('success').status).toBe('success');
  });

  it('GET deployConclusion modules still do not call GitLab Deployments — updates live in the publisher', () => {
    const deployCall = /\/projects\/[^'"\s]+\/deployments\/|protected.environments|\/environments\/.+\/|deployment_id\/approval/i;
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
    const publisher = readFileSync(
      resolve('apps/orchestrator-service/src/scans/gitlab-deployments.publisher.ts'),
      'utf8',
    );
    const egress = readFileSync(resolve('apps/orchestrator-service/src/scans/gitlab-deployments.egress.ts'), 'utf8');
    expect(egress).toMatch(/deployments\/\$\{/);
    expect(egress).toMatch(/gitlab\.com/);
    expect(publisher).toMatch(/gitlabDeploymentUrl/);
    expect(publisher).toMatch(/method: 'PUT'/);
    expect(publisher).not.toMatch(/method: 'POST'/);
    expect(egress).not.toMatch(/createDeploymentUrl|method:\s*'POST'/);
    expect(publisher).not.toMatch(/protected.environments|required.reviewers|\/approval|glab |child_process|execFile/);
    expect(egress).not.toMatch(/protected.environments|\/environments\//);
  });

  it('GitLab Commit Status and GitHub publishers stay untouched — they do not PUT GitLab Deployments', () => {
    const gitlabDeployPut = /\/deployments\/\$\{|gitlabDeploymentUrl|GitlabDeploymentsPublisher/;
    for (const rel of [
      'apps/orchestrator-service/src/scans/gitlab-statuses.publisher.ts',
      'apps/orchestrator-service/src/scans/gitlab-statuses.egress.ts',
      'apps/orchestrator-service/src/scans/github-checks.publisher.ts',
      'apps/orchestrator-service/src/scans/github-deployments.publisher.ts',
    ]) {
      const src = readFileSync(resolve(rel), 'utf8');
      expect(src, rel).not.toMatch(gitlabDeployPut);
    }
    const statusesEgress = readFileSync(
      resolve('apps/orchestrator-service/src/scans/gitlab-statuses.egress.ts'),
      'utf8',
    );
    expect(statusesEgress).not.toMatch(/\/deployments\/|\/environments\//);
    expect(gitlabCommitStatusFromScan(concludeScan(blockDeploy))).toBe('success');
  });

  it('only fail_build still drives GitLab Commit Status — block_deploy does not flip the commit status', () => {
    const failBuild = {
      status: 'succeeded' as const,
      findings: [finding],
      policies: [{ priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['fail_build'] }],
      expectedFindingCount: 1,
    };
    expect(gitlabCommitStatusFromScan(concludeScan(failBuild))).toBe('failed');
    expect(
      gitlabCommitStatusFromScan(
        concludeScan({
          ...failBuild,
          policies: [{ priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['block_deploy'] }],
        }),
      ),
    ).toBe('success');
    expect(
      parseGitlabStatusesContext({ gitlab: { projectId: PROJECT, sha: SHA, deploymentId: DEPLOYMENT_ID } }, SCAN_ID),
    ).toMatchObject({ sha: SHA, projectId: PROJECT });
  });
});

describe('GitlabDeploymentsPublisher', () => {
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

  function gitlabIntegration(over: Record<string, unknown> = {}) {
    return {
      credentialRef: 'env:GITLAB_TOKEN',
      provider: 'gitlab',
      config: { owner: 'acme', ownerType: 'group' },
      ...over,
    };
  }

  function scanRow(over: Record<string, unknown> = {}) {
    return {
      id: SCAN_ID,
      orgId: ORG_A,
      status: 'succeeded',
      scannerType: 'sca',
      options: gitlabOptions(),
      jobs: [
        {
          assetId: ASSET_A,
          findingCount: 1,
          asset: { integration: gitlabIntegration() },
        },
      ],
      ...over,
    };
  }

  function stubFetch(opts: { currentStatus?: string; putStatus?: number; getStatus?: number } = {}) {
    const fn = vi.fn(async (url: string, init?: { method?: string; body?: string }) => {
      const parsed = new URL(String(url));
      expect(parsed.protocol).toBe('https:');
      expect(parsed.pathname).toBe(
        `/api/v4/projects/${encodeURIComponent(PROJECT)}/deployments/${DEPLOYMENT_ID}`,
      );
      const method = init?.method ?? 'GET';
      expect(method).not.toBe('POST');
      if (method === 'GET') {
        return new Response(JSON.stringify({ id: DEPLOYMENT_ID, status: opts.currentStatus ?? 'running' }), {
          status: opts.getStatus ?? 200,
        });
      }
      if (method === 'PUT') {
        return new Response(JSON.stringify({ id: DEPLOYMENT_ID, status: 'failed' }), {
          status: opts.putStatus ?? 200,
        });
      }
      return new Response('unexpected', { status: 500 });
    });
    vi.stubGlobal('fetch', fn);
    return fn;
  }

  it('missing deploymentId skips the GitLab call — not a scan failure', async () => {
    const fetchMock = stubFetch();
    process.env.GITLAB_TOKEN = 'glpat-test';
    const { prisma } = prismaForScan({
      scan: scanRow({ options: { gitlab: { projectId: PROJECT } } }),
    });
    const publisher = new GitlabDeploymentsPublisher(prisma as never);
    await expect(publisher.publishForCompletedScan(ORG_A, SCAN_ID)).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('pending concludeDeploy skips publish this slice', async () => {
    const fetchMock = stubFetch();
    process.env.GITLAB_TOKEN = 'glpat-test';
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [
          {
            assetId: ASSET_A,
            findingCount: 1,
            asset: { integration: gitlabIntegration() },
          },
        ],
      }),
      findings: [],
      policies: [
        { enabled: true, priority: 10, condition: { severityAtLeast: 'high' }, actions: ['block_deploy'] },
      ],
    });
    await new GitlabDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('block_deploy match → failed status on gitlab.com via PUT, never POST create', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [
        { enabled: true, priority: 10, condition: { severityAtLeast: 'high' }, actions: ['block_deploy'] },
      ],
    });
    await new GitlabDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const methods = fetchMock.mock.calls.map((call) => (call[1] as { method?: string })?.method ?? 'GET');
    expect(methods).toContain('GET');
    expect(methods).toContain('PUT');
    expect(methods).not.toContain('POST');
    const put = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'PUT');
    expect(put).toBeTruthy();
    expect(String(put![0])).toBe(
      `https://gitlab.com/api/v4/projects/${encodeURIComponent(PROJECT)}/deployments/${DEPLOYMENT_ID}`,
    );
    const body = JSON.parse(String((put![1] as { body: string }).body)) as { status: string };
    expect(body.status).toBe('failed');
    expect(body).toEqual({ status: 'failed' });
  });

  it('matching fail_build does not fail the GitLab Deployment — Deployments stay on concludeDeploy', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [
        { enabled: true, priority: 10, condition: { severityAtLeast: 'high' }, actions: ['fail_build'] },
      ],
    });
    await new GitlabDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const put = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'PUT');
    const body = JSON.parse(String((put![1] as { body: string }).body)) as { status: string };
    expect(body.status).toBe('success');
  });

  it('no matching block_deploy → success status', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [{ enabled: true, priority: 10, condition: { kevOnly: true }, actions: ['notify'] }],
    });
    await new GitlabDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const put = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'PUT');
    const body = JSON.parse(String((put![1] as { body: string }).body)) as { status: string };
    expect(body.status).toBe('success');
  });

  it('ignores client-supplied gitlab.deployConclusion and still uses concludeDeploy', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        options: gitlabOptions({ deployConclusion: 'blocked' }),
        status: 'succeeded',
      }),
      findings: [matchingFinding],
      policies: [{ enabled: true, priority: 10, condition: { kevOnly: true }, actions: ['notify'] }],
    });
    await new GitlabDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const put = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'PUT');
    const body = JSON.parse(String((put![1] as { body: string }).body)) as { status: string };
    expect(body.status).toBe('success');
  });

  it('PUTs to the connector baseUrl host, not a free-form scan apiUrl', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        options: gitlabOptions({ apiUrl: 'https://evil.example/api/v4', host: 'evil.example' }),
        jobs: [
          {
            assetId: ASSET_A,
            findingCount: 0,
            asset: {
              integration: gitlabIntegration({ config: { owner: 'acme', ownerType: 'group', baseUrl: SELF_HOSTED } }),
            },
          },
        ],
      }),
      findings: [],
      policies: [],
    });
    await new GitlabDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    expect(fetchMock.mock.calls.length).toBeGreaterThan(0);
    for (const call of fetchMock.mock.calls) {
      const parsed = new URL(String(call[0]));
      expect(parsed.hostname).toBe('gitlab.example.com');
      expect(parsed.protocol).toBe('https:');
      expect(parsed.hostname).not.toBe('evil.example');
      expect((call[1] as { method?: string })?.method).not.toBe('POST');
    }
    const put = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'PUT');
    expect(String(put![0])).toBe(
      `${SELF_HOSTED}/api/v4/projects/${encodeURIComponent(PROJECT)}/deployments/${DEPLOYMENT_ID}`,
    );
  });

  it('skips PUT when the existing deployment status already matches', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const fetchMock = stubFetch({ currentStatus: 'success' });
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [
          {
            assetId: ASSET_A,
            findingCount: 0,
            asset: { integration: gitlabIntegration() },
          },
        ],
      }),
      findings: [],
      policies: [],
    });
    await new GitlabDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const methods = fetchMock.mock.calls.map((call) => (call[1] as { method?: string })?.method ?? 'GET');
    expect(methods).toContain('GET');
    expect(methods).not.toContain('PUT');
    expect(methods).not.toContain('POST');
  });

  it('soft-fails a GitLab API error without throwing to the lifecycle caller', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    stubFetch({ putStatus: 502 });
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [
          {
            assetId: ASSET_A,
            findingCount: 0,
            asset: { integration: gitlabIntegration() },
          },
        ],
      }),
      findings: [],
      policies: [],
    });
    await expect(
      new GitlabDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID),
    ).resolves.toBeUndefined();
  });

  it('skips when GITLAB_* credentials are unusable — fail closed, no fetch', async () => {
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [{ assetId: ASSET_A, findingCount: 0, asset: { integration: gitlabIntegration() } }],
      }),
    });
    await new GitlabDeploymentsPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('Commit Status publisher still only hits statuses when deploymentId is also present', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const urls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: { method?: string }) => {
        urls.push(`${init?.method ?? 'GET'} ${url}`);
        const parsed = new URL(String(url));
        expect(parsed.hostname).toBe('gitlab.com');
        if ((init?.method ?? 'GET') === 'GET' && parsed.pathname.includes('/repository/commits/')) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        if ((init?.method ?? 'GET') === 'POST' && parsed.pathname.includes('/statuses/')) {
          return new Response(JSON.stringify({ id: 1 }), { status: 201 });
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
          options: { gitlab: { projectId: PROJECT, sha: SHA, deploymentId: DEPLOYMENT_ID } },
          jobs: [
            {
              assetId: ASSET_A,
              findingCount: 0,
              asset: { integration: gitlabIntegration() },
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
    await new GitlabCommitStatusPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    expect(urls.some((u) => u.includes('/statuses/'))).toBe(true);
    expect(urls.some((u) => u.includes('/deployments/'))).toBe(false);
  });
});

describe('publishGitlabDeployment never leaves the allowlisted origin and never POSTs', () => {
  it('PUT/GETs only https://gitlab.com even if scan options name another host', async () => {
    const urls: string[] = [];
    const methods: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: { method?: string }) => {
        urls.push(String(url));
        methods.push(init?.method ?? 'GET');
        if ((init?.method ?? 'GET') === 'GET') {
          return new Response(JSON.stringify({ id: DEPLOYMENT_ID, status: 'running' }), { status: 200 });
        }
        return new Response(JSON.stringify({ id: DEPLOYMENT_ID, status: 'success' }), { status: 200 });
      }),
    );
    await publishGitlabDeployment({
      ctx: parseGitlabDeploymentsContext(gitlabOptions({ apiUrl: 'https://evil.example' }))!,
      origin: GITLAB_COM,
      status: 'success',
      token: 'glpat-test',
    });
    expect(urls.length).toBeGreaterThan(0);
    for (const url of urls) {
      expect(new URL(url).hostname).toBe('gitlab.com');
      expect(url.startsWith('https://gitlab.com/api/v4/')).toBe(true);
      expect(url).toContain(`/deployments/${DEPLOYMENT_ID}`);
      expect(url).not.toMatch(/\/deployments\/?$/);
    }
    expect(methods).toContain('GET');
    expect(methods).toContain('PUT');
    expect(methods).not.toContain('POST');
  });
});

describe('EXTRA_GITLAB_HOST_KEYS stay unused as the deployment origin', () => {
  it('documents the same extra-host key set as discovery / commit statuses', () => {
    expect(EXTRA_GITLAB_HOST_KEYS).toContain('apiUrl');
    expect(EXTRA_GITLAB_HOST_KEYS).toContain('host');
    expect(EXTRA_GITLAB_HOST_KEYS).toContain('gitlabHost');
  });

  it('refuseExtraGitLabHosts throws on extra tenant host fields (connector parse; scan options ignore them instead)', () => {
    expect(() => refuseExtraGitLabHosts({ owner: 'acme', apiUrl: 'https://evil.example' })).toThrow(
      /tenant-writable GitLab host/,
    );
  });
});

import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { BadRequestException } from '@nestjs/common';
import {
  CLIENT_CONCLUSION_KEYS,
  CreateScanRequest,
  concludeScan,
  findClientConclusionKeys,
} from '@ctem/contracts';
import { ZodBody } from '@ctem/service-kit';
import {
  EXTRA_GITLAB_HOST_KEYS,
  GITLAB_COM,
  GITLAB_COM_API_URL,
  GITLAB_COM_HOST,
  allowlistedGitLabApiUrl,
  createCommitStatusUrl,
  gitLabOriginFromScanJobs,
  listCommitStatusesUrl,
  parseGitLabBaseUrl,
  refuseExtraGitLabHosts,
} from './gitlab-statuses.egress';
import { parseGitLabProjectId, parseGitlabStatusesContext } from './gitlab-statuses.context';
import {
  GitlabCommitStatusPublisher,
  buildCommitStatusBody,
  publishCommitStatus,
} from './gitlab-statuses.publisher';
import { gitlabCommitStatusFromScan } from './scan-conclusion.query';

const SCAN_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_A = '4a6f9f4e-1111-4222-8333-444455556666';
const SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
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
      sha: SHA,
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

describe('GitLab Commit Status allowlist — gitlab.com or connector baseUrl', () => {
  it('accepts https://gitlab.com commit-status URLs', () => {
    expect(allowlistedGitLabApiUrl(`${GITLAB_COM_API_URL}/projects/acme%2Fapi/statuses/${SHA}`, GITLAB_COM)).toContain(
      'https://gitlab.com/api/v4/',
    );
    expect(createCommitStatusUrl(GITLAB_COM, PROJECT, SHA)).toBe(
      `https://${GITLAB_COM_HOST}/api/v4/projects/${encodeURIComponent(PROJECT)}/statuses/${SHA}`,
    );
    expect(listCommitStatusesUrl(GITLAB_COM, PROJECT, SHA, 'CTEM')).toContain(
      `https://${GITLAB_COM_HOST}/api/v4/projects/${encodeURIComponent(PROJECT)}/repository/commits/${SHA}/statuses`,
    );
  });

  it('accepts a fixture self-hosted connector baseUrl and refuses any other host', () => {
    const origin = parseGitLabBaseUrl(SELF_HOSTED);
    expect(origin).toEqual({
      host: 'gitlab.example.com',
      origin: SELF_HOSTED,
      apiUrl: `${SELF_HOSTED}/api/v4`,
    });
    expect(createCommitStatusUrl(origin, PROJECT, SHA)).toBe(
      `${SELF_HOSTED}/api/v4/projects/${encodeURIComponent(PROJECT)}/statuses/${SHA}`,
    );
    expect(() => allowlistedGitLabApiUrl('https://evil.example/api/v4/projects/1/statuses/abc', origin)).toThrow(
      /only gitlab\.example\.com is allowlisted/,
    );
    expect(() => allowlistedGitLabApiUrl(`${GITLAB_COM_API_URL}/projects/1/statuses/abc`, origin)).toThrow(
      /only gitlab\.example\.com is allowlisted/,
    );
  });

  it('refuses http, userinfo, git@, ports, and suffix-confusion', () => {
    expect(() => parseGitLabBaseUrl('http://gitlab.example.com')).toThrow(/non-https/);
    expect(() => parseGitLabBaseUrl('git@gitlab.example.com:acme/api.git')).toThrow(/git@/);
    expect(() => parseGitLabBaseUrl('https://user:pass@gitlab.example.com')).toThrow(/userinfo/);
    expect(() =>
      allowlistedGitLabApiUrl('https://user:pass@gitlab.com/api/v4/projects/1/statuses/abc', GITLAB_COM),
    ).toThrow(/userinfo/);
    expect(() =>
      allowlistedGitLabApiUrl('https://gitlab.com:8443/api/v4/projects/1/statuses/abc', GITLAB_COM),
    ).toThrow(/port/);
    expect(() =>
      allowlistedGitLabApiUrl('https://gitlab.com.evil.example/api/v4/projects/1/statuses/abc', GITLAB_COM),
    ).toThrow(/only gitlab\.com is allowlisted/);
  });

  it('refuses a free-form scan host — origin is gitlab.com or connector baseUrl, never options.gitlab.apiUrl', () => {
    const ctx = parseGitlabStatusesContext(
      gitlabOptions({
        baseUrl: 'https://evil.example',
        apiUrl: 'https://evil.example/api/v4',
        host: 'evil.example',
        gitlabHost: 'evil.example',
      }),
      SCAN_ID,
    );
    expect(ctx).toMatchObject({ projectId: PROJECT, sha: SHA });
    expect(createCommitStatusUrl(GITLAB_COM, ctx!.projectId, ctx!.sha)).toContain('https://gitlab.com/api/v4/');
    expect(createCommitStatusUrl(GITLAB_COM, ctx!.projectId, ctx!.sha)).not.toContain('evil.example');

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

describe('GitLab CI context — projectId+sha required', () => {
  it('parses options.gitlab.projectId path/with/namespace and a 40-char sha', () => {
    expect(parseGitlabStatusesContext(gitlabOptions(), SCAN_ID)).toEqual({
      projectId: PROJECT,
      sha: SHA,
      name: 'CTEM',
    });
  });

  it('parses a numeric project id and top-level allowlisted keys', () => {
    expect(parseGitLabProjectId(42)).toBe('42');
    expect(parseGitLabProjectId('42')).toBe('42');
    expect(parseGitLabProjectId('acme/platform/api')).toBe('acme/platform/api');
    expect(
      parseGitlabStatusesContext({ gitlab: { projectId: 99, sha: SHA, name: 'CTEM SCA', ref: 'main' } }, SCAN_ID),
    ).toMatchObject({ projectId: '99', name: 'CTEM SCA', ref: 'main' });
    expect(parseGitlabStatusesContext({ projectId: PROJECT, sha: SHA }, SCAN_ID)).toMatchObject({
      projectId: PROJECT,
      sha: SHA,
    });
  });

  it('skips when projectId or sha is missing or not a GitLab project id', () => {
    expect(parseGitlabStatusesContext({ gitlab: { projectId: PROJECT } }, SCAN_ID)).toBeNull();
    expect(parseGitlabStatusesContext({ gitlab: { sha: SHA } }, SCAN_ID)).toBeNull();
    expect(parseGitlabStatusesContext({ gitlab: { projectId: PROJECT, sha: 'deadbeef' } }, SCAN_ID)).toBeNull();
    expect(
      parseGitlabStatusesContext({ gitlab: { projectId: 'https://gitlab.example.com/acme/api', sha: SHA } }, SCAN_ID),
    ).toBeNull();
    expect(parseGitlabStatusesContext({ gitlab: { projectId: 'git@gitlab.com:acme/api.git', sha: SHA } }, SCAN_ID)).toBeNull();
    expect(parseGitlabStatusesContext({ gitlab: { projectId: 0, sha: SHA } }, SCAN_ID)).toBeNull();
    expect(parseGitlabStatusesContext({}, SCAN_ID)).toBeNull();
    expect(parseGitLabProjectId('acme')).toBeNull();
  });

  it('omits tenant-arbitrary targetUrl hosts and only allows CTEM_PUBLIC_URL', () => {
    process.env.CTEM_PUBLIC_URL = 'https://ctem.example';
    expect(
      parseGitlabStatusesContext(gitlabOptions({ targetUrl: 'https://evil.example/v1/scans/' + SCAN_ID }), SCAN_ID)
        ?.targetUrl,
    ).toBeUndefined();
    expect(
      parseGitlabStatusesContext(gitlabOptions({ targetUrl: `https://ctem.example/v1/scans/${SCAN_ID}` }), SCAN_ID)
        ?.targetUrl,
    ).toBe(`https://ctem.example/v1/scans/${SCAN_ID}`);
  });

  it('omits a ref that looks like a host', () => {
    expect(parseGitlabStatusesContext(gitlabOptions({ ref: 'https://evil.example' }), SCAN_ID)?.ref).toBeUndefined();
    expect(parseGitlabStatusesContext(gitlabOptions({ ref: 'feature/gate' }), SCAN_ID)?.ref).toBe('feature/gate');
  });
});

describe('client cannot write GitLab status outcome — CLIENT_CONCLUSION_KEYS stay refused', () => {
  it('ZodBody 400s conclusion keys on create; nested options.gitlab.conclusion is ignored by the publisher', () => {
    const pipe = new ZodBody(CreateScanRequest);
    for (const key of CLIENT_CONCLUSION_KEYS) {
      expect(() => pipe.transform({ scannerType: 'sca', [key]: 'failed' }), key).toThrow(BadRequestException);
      expect(() => pipe.transform({ scannerType: 'sca', options: { [key]: 'failure' } }), `options.${key}`).toThrow(
        BadRequestException,
      );
    }
    expect(findClientConclusionKeys({ scannerType: 'sca', conclusion: 'failed' })).toEqual(['conclusion']);
    expect(
      CreateScanRequest.parse({
        scannerType: 'sca',
        options: { gitlab: { projectId: PROJECT, sha: SHA, conclusion: 'failed' } },
      }),
    ).toMatchObject({ scannerType: 'sca' });
  });
});

describe('concludeScan remains source of truth for GET and GitLab status mapping', () => {
  const finding = matchingFinding;
  const failBuild = {
    status: 'succeeded' as const,
    findings: [finding],
    policies: [{ priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['fail_build'] }],
    expectedFindingCount: 1,
  };

  it('maps terminal passed → success and failed → failed; scan status is not the GitLab state', () => {
    expect(concludeScan(failBuild)).toBe('failed');
    expect(gitlabCommitStatusFromScan(concludeScan(failBuild))).toBe('failed');
    expect(
      gitlabCommitStatusFromScan(
        concludeScan({
          ...failBuild,
          policies: [{ priority: 10, condition: { kevOnly: true }, actions: ['fail_build'] }],
        }),
      ),
    ).toBe('success');
    expect(
      gitlabCommitStatusFromScan(
        concludeScan({
          ...failBuild,
          policies: [{ priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['block_deploy'] }],
        }),
      ),
    ).toBe('success');
    expect(gitlabCommitStatusFromScan('pending')).toBeNull();
    expect(buildCommitStatusBody(parseGitlabStatusesContext(gitlabOptions(), SCAN_ID)!, SCAN_ID, 'failed').state).toBe(
      'failed',
    );
    expect(buildCommitStatusBody(parseGitlabStatusesContext(gitlabOptions(), SCAN_ID)!, SCAN_ID, 'success').state).toBe(
      'success',
    );
  });

  it('GET conclusion modules still do not call GitLab statuses — statuses live in the publisher', () => {
    const gitlabStatusCall = /\/projects\/[^'"\s]+\/statuses\/|\/repository\/commits\/[^'"\s]+\/statuses/i;
    for (const rel of [
      'apps/orchestrator-service/src/scans/scans.controller.ts',
      'apps/orchestrator-service/src/scans/scan-conclusion.query.ts',
      'apps/api-gateway/src/routes/scans.controller.ts',
      'apps/risk-service/src/policy/policy-engine.service.ts',
      'libs/contracts/src/domain/scan-conclusion.ts',
      'apps/orchestrator-service/src/scans/github-checks.publisher.ts',
      'apps/orchestrator-service/src/scans/github-deployments.publisher.ts',
    ]) {
      const src = readFileSync(resolve(rel), 'utf8');
      expect(src, rel).not.toMatch(gitlabStatusCall);
    }
    const publisher = readFileSync(resolve('apps/orchestrator-service/src/scans/gitlab-statuses.publisher.ts'), 'utf8');
    const egress = readFileSync(resolve('apps/orchestrator-service/src/scans/gitlab-statuses.egress.ts'), 'utf8');
    expect(egress).toMatch(/\/statuses\//);
    expect(egress).toMatch(/gitlab\.com/);
    expect(publisher).toMatch(/createCommitStatusUrl|listCommitStatusesUrl/);
    expect(publisher).not.toMatch(/\/deployments\/|\/environments\//);
    expect(egress).not.toMatch(/\/deployments\/|\/environments\//);
    expect(publisher).not.toMatch(/glab |gitlab\s+ci\b|child_process|execFile/);
  });
});

describe('GitlabCommitStatusPublisher', () => {
  function prismaForScan(opts: {
    scan?: object | null;
    findings?: object[];
    policies?: object[];
  } = {}) {
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

  function stubFetch(opts: { existing?: object[]; postStatus?: number; getStatus?: number } = {}) {
    const fn = vi.fn(async (url: string, init?: { method?: string; body?: string }) => {
      const parsed = new URL(String(url));
      expect(parsed.protocol).toBe('https:');
      const method = init?.method ?? 'GET';
      if (method === 'GET' && parsed.pathname.includes('/repository/commits/')) {
        return new Response(JSON.stringify(opts.existing ?? []), { status: opts.getStatus ?? 200 });
      }
      if (method === 'POST' && parsed.pathname.includes('/statuses/')) {
        return new Response(JSON.stringify({ id: 91, sha: SHA }), { status: opts.postStatus ?? 201 });
      }
      return new Response('unexpected', { status: 500 });
    });
    vi.stubGlobal('fetch', fn);
    return fn;
  }

  it('missing projectId/sha skips the GitLab call — not a scan failure', async () => {
    const fetchMock = stubFetch();
    process.env.GITLAB_TOKEN = 'glpat-test';
    const { prisma } = prismaForScan({
      scan: scanRow({ options: { gitlab: { projectId: PROJECT } } }),
    });
    const publisher = new GitlabCommitStatusPublisher(prisma as never);
    await expect(publisher.publishForCompletedScan(ORG_A, SCAN_ID)).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fail_build match → failed status body on gitlab.com', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [
        { enabled: true, priority: 10, condition: { severityAtLeast: 'high' }, actions: ['fail_build'] },
      ],
    });
    await new GitlabCommitStatusPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    expect(post).toBeTruthy();
    expect(String(post![0])).toBe(
      `https://gitlab.com/api/v4/projects/${encodeURIComponent(PROJECT)}/statuses/${SHA}`,
    );
    const body = JSON.parse(String((post![1] as { body: string }).body)) as {
      state: string;
      name: string;
      description: string;
    };
    expect(body.state).toBe('failed');
    expect(body.name).toBe('CTEM');
    expect(body.description).toContain(SCAN_ID);
  });

  it('matching block_deploy does not fail the GitLab status — statuses stay on concludeScan', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [
        { enabled: true, priority: 10, condition: { severityAtLeast: 'high' }, actions: ['block_deploy'] },
      ],
    });
    await new GitlabCommitStatusPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    const body = JSON.parse(String((post![1] as { body: string }).body)) as { state: string };
    expect(body.state).toBe('success');
  });

  it('no matching fail_build → success status body', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [{ enabled: true, priority: 10, condition: { kevOnly: true }, actions: ['notify'] }],
    });
    await new GitlabCommitStatusPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    const body = JSON.parse(String((post![1] as { body: string }).body)) as { state: string };
    expect(body.state).toBe('success');
  });

  it('ignores client-supplied gitlab.conclusion and still uses concludeScan', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        options: gitlabOptions({ conclusion: 'failed' }),
        status: 'succeeded',
      }),
      findings: [matchingFinding],
      policies: [{ enabled: true, priority: 10, condition: { kevOnly: true }, actions: ['notify'] }],
    });
    await new GitlabCommitStatusPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    const body = JSON.parse(String((post![1] as { body: string }).body)) as { state: string };
    expect(body.state).toBe('success');
  });

  it('POSTs to the connector baseUrl host, not a free-form scan apiUrl', async () => {
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
    await new GitlabCommitStatusPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    expect(fetchMock.mock.calls.length).toBeGreaterThan(0);
    for (const call of fetchMock.mock.calls) {
      const parsed = new URL(String(call[0]));
      expect(parsed.hostname).toBe('gitlab.example.com');
      expect(parsed.protocol).toBe('https:');
      expect(parsed.hostname).not.toBe('evil.example');
    }
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    expect(String(post![0])).toBe(
      `${SELF_HOSTED}/api/v4/projects/${encodeURIComponent(PROJECT)}/statuses/${SHA}`,
    );
  });

  it('skips a second POST when an equivalent status for this scanId already exists', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    const fetchMock = stubFetch({
      existing: [{ id: 7, name: 'CTEM', description: `CTEM scan ${SCAN_ID} passed`, sha: SHA }],
    });
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
    await new GitlabCommitStatusPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const methods = fetchMock.mock.calls.map((call) => (call[1] as { method?: string })?.method ?? 'GET');
    expect(methods).toContain('GET');
    expect(methods).not.toContain('POST');
  });

  it('soft-fails a GitLab API error without throwing to the lifecycle caller', async () => {
    process.env.GITLAB_TOKEN = 'glpat-test';
    stubFetch({ postStatus: 502 });
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
      new GitlabCommitStatusPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID),
    ).resolves.toBeUndefined();
  });

  it('skips when GITLAB_* credentials are unusable — fail closed, no fetch', async () => {
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [{ assetId: ASSET_A, findingCount: 0, asset: { integration: gitlabIntegration() } }],
      }),
    });
    await new GitlabCommitStatusPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('publishCommitStatus never leaves the allowlisted origin', () => {
  it('POSTs only to https://gitlab.com even if scan options name another host', async () => {
    const urls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        urls.push(String(url));
        const parsed = new URL(String(url));
        if (parsed.pathname.includes('/repository/commits/')) {
          return new Response(JSON.stringify([]), { status: 200 });
        }
        return new Response(JSON.stringify({ id: 1 }), { status: 201 });
      }),
    );
    await publishCommitStatus({
      ctx: parseGitlabStatusesContext(gitlabOptions({ apiUrl: 'https://evil.example' }), SCAN_ID)!,
      origin: GITLAB_COM,
      scanId: SCAN_ID,
      state: 'success',
      token: 'glpat-test',
    });
    expect(urls.length).toBeGreaterThan(0);
    for (const url of urls) {
      expect(new URL(url).hostname).toBe('gitlab.com');
      expect(url.startsWith('https://gitlab.com/api/v4/')).toBe(true);
    }
  });
});

describe('EXTRA_GITLAB_HOST_KEYS stay unused as the status origin', () => {
  it('documents the same extra-host key set as discovery', () => {
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

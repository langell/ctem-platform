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
  GITHUB_API_HOST,
  allowlistedGithubApiUrl,
  checkRunUrl,
  checkRunsUrl,
  githubChecksApiUrl,
  listCheckRunsUrl,
} from './github-checks.egress';
import { parseGithubChecksContext } from './github-checks.context';
import { GithubChecksPublisher, buildCheckRunBody, upsertCheckRun } from './github-checks.publisher';
import { checkConclusionFromScan } from './scan-conclusion.query';

const SCAN_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_A = '4a6f9f4e-1111-4222-8333-444455556666';
const SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
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
      sha: SHA,
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

describe('GitHub Checks allowlist — only api.github.com', () => {
  it('accepts https://api.github.com check-runs URLs', () => {
    expect(allowlistedGithubApiUrl('https://api.github.com/repos/acme/api/check-runs')).toBe(
      'https://api.github.com/repos/acme/api/check-runs',
    );
    expect(checkRunsUrl('acme', 'api')).toBe(`https://${GITHUB_API_HOST}/repos/acme/api/check-runs`);
    expect(checkRunUrl('acme', 'api', 42)).toBe(`https://${GITHUB_API_HOST}/repos/acme/api/check-runs/42`);
    expect(listCheckRunsUrl('acme', 'api', SHA, 'CTEM')).toContain(
      `https://${GITHUB_API_HOST}/repos/acme/api/commits/${SHA}/check-runs`,
    );
  });

  it('refuses GitHub Enterprise, github.com, suffix-confusion, http, userinfo, and ports', () => {
    expect(() => allowlistedGithubApiUrl('https://github.example.com/api/v3/repos/acme/api/check-runs')).toThrow(
      /only api\.github\.com/,
    );
    expect(() => allowlistedGithubApiUrl('https://ghe.internal/api/v3/check-runs')).toThrow(/only api\.github\.com/);
    expect(() => allowlistedGithubApiUrl('https://github.com/acme/api')).toThrow(/only api\.github\.com/);
    expect(() => allowlistedGithubApiUrl('https://api.github.com.evil.example/repos/acme/api')).toThrow(
      /only api\.github\.com/,
    );
    expect(() => allowlistedGithubApiUrl('http://api.github.com/repos/acme/api/check-runs')).toThrow(/non-https/);
    expect(() => allowlistedGithubApiUrl('https://user:pass@api.github.com/repos/acme/api/check-runs')).toThrow(
      /userinfo/,
    );
    expect(() => allowlistedGithubApiUrl('https://api.github.com:8443/repos/acme/api/check-runs')).toThrow(/port/);
  });

  it('does not follow GITHUB_API_URL or tenant baseUrl off api.github.com', () => {
    process.env.GITHUB_API_URL = 'https://github.example.com/api/v3';
    expect(githubChecksApiUrl('/repos/acme/api/check-runs')).toBe(
      'https://api.github.com/repos/acme/api/check-runs',
    );
    const ctx = parseGithubChecksContext(
      {
        github: {
          repository: 'acme/api',
          sha: SHA,
          baseUrl: 'https://github.example.com/api/v3',
          githubHost: 'github.example.com',
        },
      },
      SCAN_ID,
    );
    expect(ctx).toMatchObject({ owner: 'acme', repo: 'api', sha: SHA });
    expect(checkRunsUrl(ctx!.owner, ctx!.repo)).toBe('https://api.github.com/repos/acme/api/check-runs');
  });
});

describe('GitHub Checks context — repository+sha required', () => {
  it('parses options.github.repository owner/name and a 40-char sha', () => {
    expect(parseGithubChecksContext(githubOptions(), SCAN_ID)).toEqual({
      owner: 'acme',
      repo: 'api',
      sha: SHA,
      checkName: 'CTEM',
    });
  });

  it('parses owner+repo and top-level allowlisted keys', () => {
    expect(
      parseGithubChecksContext({ github: { owner: 'acme', repo: 'api', sha: SHA, checkName: 'CTEM SCA' } }, SCAN_ID),
    ).toMatchObject({ owner: 'acme', repo: 'api', checkName: 'CTEM SCA' });
    expect(parseGithubChecksContext({ repository: 'acme/api', sha: SHA }, SCAN_ID)).toMatchObject({
      owner: 'acme',
      repo: 'api',
    });
  });

  it('skips when sha or repository is missing or not a github.com owner/name', () => {
    expect(parseGithubChecksContext({ github: { repository: 'acme/api' } }, SCAN_ID)).toBeNull();
    expect(parseGithubChecksContext({ github: { sha: SHA } }, SCAN_ID)).toBeNull();
    expect(parseGithubChecksContext({ github: { repository: 'acme/api', sha: 'deadbeef' } }, SCAN_ID)).toBeNull();
    expect(
      parseGithubChecksContext({ github: { repository: 'https://github.example.com/acme/api', sha: SHA } }, SCAN_ID),
    ).toBeNull();
    expect(parseGithubChecksContext({ github: { repository: 'github.com/acme/api', sha: SHA } }, SCAN_ID)).toBeNull();
    expect(parseGithubChecksContext({}, SCAN_ID)).toBeNull();
  });

  it('omits tenant-arbitrary detailsUrl hosts and only allows CTEM_PUBLIC_URL', () => {
    process.env.CTEM_PUBLIC_URL = 'https://ctem.example';
    expect(
      parseGithubChecksContext(
        githubOptions({ detailsUrl: 'https://evil.example/v1/scans/' + SCAN_ID }),
        SCAN_ID,
      )?.detailsUrl,
    ).toBeUndefined();
    expect(
      parseGithubChecksContext(
        githubOptions({ detailsUrl: `https://ctem.example/v1/scans/${SCAN_ID}` }),
        SCAN_ID,
      )?.detailsUrl,
    ).toBe(`https://ctem.example/v1/scans/${SCAN_ID}`);
  });
});

describe('client cannot write Check conclusion — CLIENT_CONCLUSION_KEYS stay refused', () => {
  it('ZodBody 400s conclusion keys on create; nested options.github.conclusion is ignored by the publisher', () => {
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
        options: { github: { repository: 'acme/api', sha: SHA, conclusion: 'failure' } },
      }),
    ).toMatchObject({ scannerType: 'sca' });
  });
});

describe('concludeScan remains source of truth for GET and Checks mapping', () => {
  const finding = matchingFinding;
  const failBuild = {
    status: 'succeeded' as const,
    findings: [finding],
    policies: [{ priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['fail_build'] }],
    expectedFindingCount: 1,
  };

  it('maps terminal passed → success and failed → failure; scan status is not the Check conclusion', () => {
    expect(concludeScan(failBuild)).toBe('failed');
    expect(checkConclusionFromScan(concludeScan(failBuild))).toBe('failure');
    expect(
      checkConclusionFromScan(
        concludeScan({
          ...failBuild,
          policies: [{ priority: 10, condition: { kevOnly: true }, actions: ['fail_build'] }],
        }),
      ),
    ).toBe('success');
    expect(checkConclusionFromScan('pending')).toBeNull();
    expect(buildCheckRunBody(parseGithubChecksContext(githubOptions(), SCAN_ID)!, SCAN_ID, 'failure').conclusion).toBe(
      'failure',
    );
    expect(buildCheckRunBody(parseGithubChecksContext(githubOptions(), SCAN_ID)!, SCAN_ID, 'success').conclusion).toBe(
      'success',
    );
  });

  it('GET conclusion modules still do not call check-runs — Checks live in the publisher', () => {
    const checksCall = /check-runs|check-suites|checks\.create/i;
    for (const rel of [
      'apps/orchestrator-service/src/scans/scans.controller.ts',
      'apps/orchestrator-service/src/scans/scan-conclusion.query.ts',
      'apps/api-gateway/src/routes/scans.controller.ts',
      'apps/risk-service/src/policy/policy-engine.service.ts',
      'libs/contracts/src/domain/scan-conclusion.ts',
    ]) {
      const src = readFileSync(resolve(rel), 'utf8');
      expect(src, rel).not.toMatch(checksCall);
    }
    const publisher = readFileSync(resolve('apps/orchestrator-service/src/scans/github-checks.publisher.ts'), 'utf8');
    const egress = readFileSync(resolve('apps/orchestrator-service/src/scans/github-checks.egress.ts'), 'utf8');
    expect(egress).toMatch(/check-runs/);
    expect(egress).toMatch(/api\.github\.com/);
    expect(publisher).toMatch(/checkRunsUrl|listCheckRunsUrl|checkRunUrl/);
    expect(publisher).not.toMatch(/github\.example\.com|GITHUB_API_URL/);
    expect(egress).not.toMatch(/github\.example\.com/);
  });
});

describe('GithubChecksPublisher', () => {
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

  function stubFetch(opts: { listIds?: number[]; postStatus?: number; patchStatus?: number } = {}) {
    const fn = vi.fn(async (url: string, init?: { method?: string; body?: string }) => {
      const parsed = new URL(String(url));
      expect(parsed.hostname).toBe('api.github.com');
      expect(parsed.protocol).toBe('https:');
      const method = init?.method ?? 'GET';
      if (method === 'GET' && parsed.pathname.includes('/commits/')) {
        const check_runs = (opts.listIds ?? []).map((id) => ({ id, external_id: SCAN_ID, name: 'CTEM' }));
        return new Response(JSON.stringify({ total_count: check_runs.length, check_runs }), { status: 200 });
      }
      if (method === 'POST') {
        return new Response(JSON.stringify({ id: 99, external_id: SCAN_ID }), {
          status: opts.postStatus ?? 201,
        });
      }
      if (method === 'PATCH') {
        return new Response(JSON.stringify({ id: opts.listIds?.[0] ?? 7 }), {
          status: opts.patchStatus ?? 200,
        });
      }
      return new Response('unexpected', { status: 500 });
    });
    vi.stubGlobal('fetch', fn);
    return fn;
  }

  it('missing sha/repo skips the Check call — not a scan failure', async () => {
    const fetchMock = stubFetch();
    process.env.GITHUB_TOKEN = 'ghp_test';
    const { prisma } = prismaForScan({
      scan: scanRow({ options: { github: { repository: 'acme/api' } } }),
    });
    const publisher = new GithubChecksPublisher(prisma as never);
    await expect(publisher.publishForCompletedScan(ORG_A, SCAN_ID)).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fail_build match → failure Check body on api.github.com', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [
        { enabled: true, priority: 10, condition: { severityAtLeast: 'high' }, actions: ['fail_build'] },
      ],
    });
    await new GithubChecksPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    expect(post).toBeTruthy();
    expect(String(post![0])).toBe('https://api.github.com/repos/acme/api/check-runs');
    const body = JSON.parse(String((post![1] as { body: string }).body)) as {
      conclusion: string;
      head_sha: string;
      external_id: string;
    };
    expect(body.conclusion).toBe('failure');
    expect(body.head_sha).toBe(SHA);
    expect(body.external_id).toBe(SCAN_ID);
  });

  it('no matching fail_build → success Check body', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [{ enabled: true, priority: 10, condition: { kevOnly: true }, actions: ['notify'] }],
    });
    await new GithubChecksPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    const body = JSON.parse(String((post![1] as { body: string }).body)) as { conclusion: string };
    expect(body.conclusion).toBe('success');
  });

  it('ignores client-supplied github.conclusion and still uses concludeScan', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        options: githubOptions({ conclusion: 'failure' }),
        status: 'succeeded',
      }),
      findings: [matchingFinding],
      policies: [{ enabled: true, priority: 10, condition: { kevOnly: true }, actions: ['notify'] }],
    });
    await new GithubChecksPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const post = fetchMock.mock.calls.find((call) => (call[1] as { method?: string })?.method === 'POST');
    const body = JSON.parse(String((post![1] as { body: string }).body)) as { conclusion: string };
    expect(body.conclusion).toBe('success');
  });

  it('PATCHes an existing Check Run with the same scanId instead of creating another', async () => {
    process.env.GITHUB_TOKEN = 'ghp_test';
    const fetchMock = stubFetch({ listIds: [77] });
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
    await new GithubChecksPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    const methods = fetchMock.mock.calls.map((call) => (call[1] as { method?: string })?.method ?? 'GET');
    expect(methods).toContain('GET');
    expect(methods).toContain('PATCH');
    expect(methods).not.toContain('POST');
    expect(String(fetchMock.mock.calls.find((c) => (c[1] as { method?: string })?.method === 'PATCH')![0])).toBe(
      'https://api.github.com/repos/acme/api/check-runs/77',
    );
  });

  it('soft-fails a Check API error without throwing to the lifecycle caller', async () => {
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
      new GithubChecksPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID),
    ).resolves.toBeUndefined();
  });

  it('skips when GITHUB_* credentials are unusable — fail closed, no fetch', async () => {
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [{ assetId: ASSET_A, findingCount: 0, asset: { integration: { credentialRef: 'env:GITHUB_TOKEN' } } }],
      }),
    });
    await new GithubChecksPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('upsertCheckRun never leaves api.github.com', () => {
  it('POSTs only to https://api.github.com even if GITHUB_API_URL is enterprise', async () => {
    process.env.GITHUB_API_URL = 'https://github.example.com/api/v3';
    const urls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        urls.push(String(url));
        const parsed = new URL(String(url));
        if (parsed.pathname.includes('/commits/')) {
          return new Response(JSON.stringify({ check_runs: [] }), { status: 200 });
        }
        return new Response(JSON.stringify({ id: 1 }), { status: 201 });
      }),
    );
    await upsertCheckRun({
      ctx: parseGithubChecksContext(githubOptions(), SCAN_ID)!,
      scanId: SCAN_ID,
      conclusion: 'success',
      token: 'ghp_test',
    });
    expect(urls.length).toBeGreaterThan(0);
    for (const url of urls) {
      expect(new URL(url).hostname).toBe('api.github.com');
      expect(url.startsWith('https://api.github.com/')).toBe(true);
    }
  });
});

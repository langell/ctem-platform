import { afterEach, describe, expect, it, vi } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { BadRequestException } from '@nestjs/common';
import {
  CLIENT_CONCLUSION_KEYS,
  CreateScanRequest,
  concludeScan,
  findClientConclusionKeys,
} from '@ctem/contracts';
import { ZodBody } from '@ctem/service-kit';
import {
  BITBUCKET_API_HOST,
  BITBUCKET_API_ORIGIN,
  TENANT_BITBUCKET_HOST_KEYS,
  allowlistedBitbucketBuildStatusUrl,
  bitbucketBuildStatusUrl,
  refuseTenantBitbucketHost,
} from './bitbucket-statuses.egress';
import {
  bitbucketStatusKey,
  parseBitbucketRepoSlug,
  parseBitbucketStatusesContext,
  parseBitbucketWorkspace,
} from './bitbucket-statuses.context';
import {
  BitbucketBuildStatusPublisher,
  buildBitbucketBuildStatusBody,
  publishBitbucketBuildStatus,
} from './bitbucket-statuses.publisher';
import { bitbucketBuildStateFromScan } from './scan-conclusion.query';

const SCAN_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_A = '4a6f9f4e-1111-4222-8333-444455556666';
const SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ASSET_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
const FINDING_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2';
const WORKSPACE = 'langell';
const REPO = 'ctem-platform';
const STATUS_URL = `${BITBUCKET_API_ORIGIN}/2.0/repositories/${WORKSPACE}/${REPO}/commit/${SHA}/statuses/build`;

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

function bitbucketOptions(over: Record<string, unknown> = {}) {
  return {
    bitbucket: {
      workspace: WORKSPACE,
      repoSlug: REPO,
      sha: SHA,
      ...over,
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.BITBUCKET_TOKEN;
  delete process.env.BITBUCKET_INT_TOKEN;
  delete process.env.CTEM_PUBLIC_URL;
});

describe('Bitbucket Cloud build-status allowlist — exact api.bitbucket.org', () => {
  it('accepts https://api.bitbucket.org build-status URLs', () => {
    expect(allowlistedBitbucketBuildStatusUrl(STATUS_URL, WORKSPACE, REPO, SHA)).toBe(STATUS_URL);
    expect(bitbucketBuildStatusUrl(WORKSPACE, REPO, SHA)).toBe(STATUS_URL);
    expect(new URL(STATUS_URL).hostname).toBe(BITBUCKET_API_HOST);
    expect(STATUS_URL).toContain('/statuses/build');
  });

  it('refuses Server, lookalike, bitbucket.org HTML, http, userinfo, and non-443 ports', () => {
    const path = `/2.0/repositories/${WORKSPACE}/${REPO}/commit/${SHA}/statuses/build`;
    expect(() =>
      allowlistedBitbucketBuildStatusUrl(
        `https://bitbucket.example.com${path}`,
        WORKSPACE,
        REPO,
        SHA,
      ),
    ).toThrow(/only api\.bitbucket\.org is allowlisted/);
    expect(() =>
      allowlistedBitbucketBuildStatusUrl(
        `https://api.bitbucket.org.evil.example${path}`,
        WORKSPACE,
        REPO,
        SHA,
      ),
    ).toThrow(/only api\.bitbucket\.org is allowlisted/);
    expect(() =>
      allowlistedBitbucketBuildStatusUrl(
        `https://evil.api.bitbucket.org${path}`,
        WORKSPACE,
        REPO,
        SHA,
      ),
    ).toThrow(/only api\.bitbucket\.org is allowlisted/);
    expect(() =>
      allowlistedBitbucketBuildStatusUrl(`https://bitbucket.org${path}`, WORKSPACE, REPO, SHA),
    ).toThrow(/only api\.bitbucket\.org is allowlisted/);
    expect(() =>
      allowlistedBitbucketBuildStatusUrl(`https://api-bitbucket.org${path}`, WORKSPACE, REPO, SHA),
    ).toThrow(/only api\.bitbucket\.org is allowlisted/);
    expect(() =>
      allowlistedBitbucketBuildStatusUrl(`http://api.bitbucket.org${path}`, WORKSPACE, REPO, SHA),
    ).toThrow(/non-https/);
    expect(() =>
      allowlistedBitbucketBuildStatusUrl(
        `https://user:token@api.bitbucket.org${path}`,
        WORKSPACE,
        REPO,
        SHA,
      ),
    ).toThrow(/userinfo/);
    expect(() =>
      allowlistedBitbucketBuildStatusUrl(
        `https://api.bitbucket.org:8443${path}`,
        WORKSPACE,
        REPO,
        SHA,
      ),
    ).toThrow(/port/);
    expect(() =>
      allowlistedBitbucketBuildStatusUrl(
        `https://api.bitbucket.org/rest/api/1.0/projects/ACME/repos/${REPO}/commits/${SHA}`,
        WORKSPACE,
        REPO,
        SHA,
      ),
    ).toThrow(/statuses\/build/);
  });

  it('refuses tenant baseUrl, apiUrl, and bitbucketHost as an endpoint', () => {
    for (const key of [
      'baseUrl',
      'apiUrl',
      'bitbucketHost',
      'bitbucketServerUrl',
      'dataCenterUrl',
    ] as const) {
      expect(() =>
        refuseTenantBitbucketHost({ workspace: WORKSPACE, [key]: 'https://bitbucket.internal' }),
      ).toThrow(new RegExp(key));
    }
    expect(TENANT_BITBUCKET_HOST_KEYS).toContain('baseUrl');
    expect(TENANT_BITBUCKET_HOST_KEYS).toContain('apiUrl');
    expect(TENANT_BITBUCKET_HOST_KEYS).toContain('bitbucketHost');
  });

  it('does not let scan host fields choose the API host', () => {
    const ctx = parseBitbucketStatusesContext(
      bitbucketOptions({
        baseUrl: 'https://bitbucket.internal',
        apiUrl: 'https://bitbucket.example.com',
        bitbucketHost: 'bitbucket.example.com',
        host: 'bitbucket.example.com',
      }),
      SCAN_ID,
    );
    expect(ctx).toMatchObject({ workspace: WORKSPACE, repoSlug: REPO, sha: SHA });
    const url = bitbucketBuildStatusUrl(ctx!.workspace, ctx!.repoSlug, ctx!.sha);
    expect(url).toBe(STATUS_URL);
    expect(url).not.toContain('bitbucket.internal');
    expect(url).not.toContain('bitbucket.example.com');
  });
});

describe('Bitbucket CI context — workspace+repoSlug+sha required', () => {
  it('parses options.bitbucket workspace, repoSlug, and a 40-char sha', () => {
    expect(parseBitbucketStatusesContext(bitbucketOptions(), SCAN_ID)).toEqual({
      workspace: WORKSPACE,
      repoSlug: REPO,
      sha: SHA,
      key: `ctem-scan-${SCAN_ID}`,
      name: 'CTEM',
    });
  });

  it('accepts repository as a repo-slug alias and top-level allowlisted keys', () => {
    expect(parseBitbucketRepoSlug(REPO)).toBe(REPO);
    expect(parseBitbucketWorkspace(WORKSPACE)).toBe(WORKSPACE);
    expect(
      parseBitbucketStatusesContext(
        { bitbucket: { workspace: WORKSPACE, repository: REPO, sha: SHA, name: 'CTEM SCA' } },
        SCAN_ID,
      ),
    ).toMatchObject({ repoSlug: REPO, name: 'CTEM SCA', key: `ctem-scan-${SCAN_ID}` });
    expect(
      parseBitbucketStatusesContext({ workspace: WORKSPACE, repoSlug: REPO, sha: SHA }, SCAN_ID),
    ).toMatchObject({ workspace: WORKSPACE, repoSlug: REPO, sha: SHA });
  });

  it('skips when workspace, repo slug, or sha is missing or not an identifier', () => {
    expect(
      parseBitbucketStatusesContext(
        { bitbucket: { workspace: WORKSPACE, repoSlug: REPO } },
        SCAN_ID,
      ),
    ).toBeNull();
    expect(
      parseBitbucketStatusesContext({ bitbucket: { workspace: WORKSPACE, sha: SHA } }, SCAN_ID),
    ).toBeNull();
    expect(
      parseBitbucketStatusesContext({ bitbucket: { repoSlug: REPO, sha: SHA } }, SCAN_ID),
    ).toBeNull();
    expect(
      parseBitbucketStatusesContext(
        { bitbucket: { workspace: WORKSPACE, repoSlug: REPO, sha: 'deadbeef' } },
        SCAN_ID,
      ),
    ).toBeNull();
    expect(
      parseBitbucketStatusesContext(
        { bitbucket: { workspace: 'https://bitbucket.example.com', repoSlug: REPO, sha: SHA } },
        SCAN_ID,
      ),
    ).toBeNull();
    expect(
      parseBitbucketStatusesContext(
        {
          bitbucket: {
            workspace: WORKSPACE,
            repoSlug: 'https://bitbucket.org/langell/ctem-platform',
            sha: SHA,
          },
        },
        SCAN_ID,
      ),
    ).toBeNull();
    expect(
      parseBitbucketStatusesContext(
        { bitbucket: { workspace: 'api.bitbucket.org', repoSlug: REPO, sha: SHA } },
        SCAN_ID,
      ),
    ).toBeNull();
    expect(
      parseBitbucketStatusesContext(
        { bitbucket: { workspace: WORKSPACE, repository: 'acme/api', sha: SHA } },
        SCAN_ID,
      ),
    ).toBeNull();
    expect(parseBitbucketWorkspace('acme/../other')).toBeNull();
    expect(parseBitbucketStatusesContext({}, SCAN_ID)).toBeNull();
  });

  it('omits tenant-arbitrary url hosts and only allows CTEM_PUBLIC_URL', () => {
    process.env.CTEM_PUBLIC_URL = 'https://ctem.example';
    expect(
      parseBitbucketStatusesContext(
        bitbucketOptions({ url: 'https://evil.example/v1/scans/' + SCAN_ID }),
        SCAN_ID,
      )?.url,
    ).toBeUndefined();
    expect(
      parseBitbucketStatusesContext(
        bitbucketOptions({ url: `https://ctem.example/v1/scans/${SCAN_ID}` }),
        SCAN_ID,
      )?.url,
    ).toBe(`https://ctem.example/v1/scans/${SCAN_ID}`);
  });

  it('keeps one stable key for a scanId — a URL-shaped key falls back to ctem-scan-{scanId}', () => {
    expect(bitbucketStatusKey(SCAN_ID, undefined)).toBe(`ctem-scan-${SCAN_ID}`);
    expect(bitbucketStatusKey(SCAN_ID, 'ctem-custom')).toBe('ctem-custom');
    expect(bitbucketStatusKey(SCAN_ID, 'https://evil.example/status')).toBe(`ctem-scan-${SCAN_ID}`);
    const failed = buildBitbucketBuildStatusBody(
      parseBitbucketStatusesContext(bitbucketOptions(), SCAN_ID)!,
      SCAN_ID,
      'FAILED',
    );
    const passed = buildBitbucketBuildStatusBody(
      parseBitbucketStatusesContext(bitbucketOptions(), SCAN_ID)!,
      SCAN_ID,
      'SUCCESSFUL',
    );
    expect(failed.key).toBe(passed.key);
    expect(failed.key).toBe(`ctem-scan-${SCAN_ID}`);
    expect(new Set([failed.key, passed.key]).size).toBe(1);
  });
});

describe('client cannot write Bitbucket status outcome — CLIENT_CONCLUSION_KEYS stay refused', () => {
  it('ZodBody 400s conclusion keys on create; nested options.bitbucket.conclusion is ignored by the publisher', () => {
    const pipe = new ZodBody(CreateScanRequest);
    for (const key of CLIENT_CONCLUSION_KEYS) {
      expect(() => pipe.transform({ scannerType: 'sca', [key]: 'failed' }), key).toThrow(
        BadRequestException,
      );
      expect(
        () => pipe.transform({ scannerType: 'sca', options: { [key]: 'failure' } }),
        `options.${key}`,
      ).toThrow(BadRequestException);
    }
    expect(findClientConclusionKeys({ scannerType: 'sca', conclusion: 'failed' })).toEqual([
      'conclusion',
    ]);
    expect(
      CreateScanRequest.parse({
        scannerType: 'sca',
        options: {
          bitbucket: {
            workspace: WORKSPACE,
            repoSlug: REPO,
            sha: SHA,
            conclusion: 'failed',
            state: 'FAILED',
          },
        },
      }),
    ).toMatchObject({ scannerType: 'sca' });
  });
});

describe('concludeScan remains source of truth for GET and Bitbucket status mapping', () => {
  const finding = matchingFinding;
  const failBuild = {
    status: 'succeeded' as const,
    findings: [finding],
    policies: [
      { priority: 10, condition: { severityAtLeast: 'high' as const }, actions: ['fail_build'] },
    ],
    expectedFindingCount: 1,
  };

  it('maps terminal failed → FAILED and passed → SUCCESSFUL; pending is not published', () => {
    expect(concludeScan(failBuild)).toBe('failed');
    expect(bitbucketBuildStateFromScan(concludeScan(failBuild))).toBe('FAILED');
    expect(
      bitbucketBuildStateFromScan(
        concludeScan({
          ...failBuild,
          policies: [{ priority: 10, condition: { kevOnly: true }, actions: ['fail_build'] }],
        }),
      ),
    ).toBe('SUCCESSFUL');
    expect(
      bitbucketBuildStateFromScan(
        concludeScan({
          ...failBuild,
          policies: [
            {
              priority: 10,
              condition: { severityAtLeast: 'high' as const },
              actions: ['block_deploy'],
            },
          ],
        }),
      ),
    ).toBe('SUCCESSFUL');
    expect(bitbucketBuildStateFromScan('pending')).toBeNull();
    expect(
      buildBitbucketBuildStatusBody(
        parseBitbucketStatusesContext(bitbucketOptions(), SCAN_ID)!,
        SCAN_ID,
        'FAILED',
      ).state,
    ).toBe('FAILED');
    expect(
      buildBitbucketBuildStatusBody(
        parseBitbucketStatusesContext(bitbucketOptions(), SCAN_ID)!,
        SCAN_ID,
        'SUCCESSFUL',
      ).state,
    ).toBe('SUCCESSFUL');
  });

  it('GET conclusion modules and GitHub/GitLab publishers do not call Bitbucket; notification-service is untouched', () => {
    const bitbucketCall = /api\.bitbucket\.org|statuses\/build|BitbucketBuildStatusPublisher/;
    for (const rel of [
      'apps/orchestrator-service/src/scans/scans.controller.ts',
      'apps/orchestrator-service/src/scans/scan-conclusion.query.ts',
      'apps/api-gateway/src/routes/scans.controller.ts',
      'apps/orchestrator-service/src/scans/github-checks.publisher.ts',
      'apps/orchestrator-service/src/scans/github-checks.egress.ts',
      'apps/orchestrator-service/src/scans/github-deployments.publisher.ts',
      'apps/orchestrator-service/src/scans/gitlab-statuses.publisher.ts',
      'apps/orchestrator-service/src/scans/gitlab-statuses.egress.ts',
      'apps/orchestrator-service/src/scans/gitlab-deployments.publisher.ts',
    ]) {
      const src = readFileSync(resolve(rel), 'utf8');
      expect(src, rel).not.toMatch(bitbucketCall);
    }
    const notifyFiles = tsFiles(resolve('apps/notification-service'));
    expect(notifyFiles.length).toBeGreaterThan(0);
    for (const file of notifyFiles) {
      expect(readFileSync(file, 'utf8'), file).not.toMatch(bitbucketCall);
    }
    const publisher = readFileSync(
      resolve('apps/orchestrator-service/src/scans/bitbucket-statuses.publisher.ts'),
      'utf8',
    );
    const egress = readFileSync(
      resolve('apps/orchestrator-service/src/scans/bitbucket-statuses.egress.ts'),
      'utf8',
    );
    expect(egress).toMatch(/api\.bitbucket\.org/);
    expect(egress).toMatch(/\/statuses\/build/);
    expect(publisher).toMatch(/bitbucketBuildStatusUrl/);
    expect(publisher).toMatch(/ctem-scan-/);
    expect(publisher).not.toMatch(/concludeDeploy\(|randomUUID|Date\.now|child_process|execFile/);
    expect(egress).not.toMatch(/\/deployments\/|\/rest\/api\/1\.0/);
  });
});

describe('BitbucketBuildStatusPublisher', () => {
  function prismaForScan(
    opts: { scan?: object | null; findings?: object[]; policies?: object[] } = {},
  ) {
    const tx = {
      scan: { findUnique: vi.fn(async () => opts.scan ?? null), update: vi.fn() },
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

  function bitbucketIntegration(over: Record<string, unknown> = {}) {
    return {
      credentialRef: 'env:BITBUCKET_TOKEN',
      provider: 'bitbucket',
      config: { workspace: WORKSPACE },
      ...over,
    };
  }

  function scanRow(over: Record<string, unknown> = {}) {
    return {
      id: SCAN_ID,
      orgId: ORG_A,
      status: 'succeeded',
      scannerType: 'sca',
      options: bitbucketOptions(),
      jobs: [
        {
          assetId: ASSET_A,
          findingCount: 1,
          asset: { integration: bitbucketIntegration() },
        },
      ],
      ...over,
    };
  }

  function stubFetch(opts: { postStatus?: number } = {}) {
    const fn = vi.fn(async (url: string, init?: { method?: string; body?: string }) => {
      const parsed = new URL(String(url));
      expect(parsed.protocol).toBe('https:');
      expect(parsed.hostname).toBe(BITBUCKET_API_HOST);
      const method = init?.method ?? 'GET';
      if (method === 'POST' && parsed.pathname.endsWith('/statuses/build')) {
        return new Response(JSON.stringify({ key: `ctem-scan-${SCAN_ID}`, state: 'SUCCESSFUL' }), {
          status: opts.postStatus ?? 201,
        });
      }
      return new Response('unexpected', { status: 500 });
    });
    vi.stubGlobal('fetch', fn);
    return fn;
  }

  function postBodies(
    fetchMock: ReturnType<typeof stubFetch>,
  ): Array<{ key: string; state: string; url?: string }> {
    return fetchMock.mock.calls
      .filter((call) => (call[1] as { method?: string })?.method === 'POST')
      .map(
        (call) =>
          JSON.parse(String((call[1] as { body: string }).body)) as { key: string; state: string },
      );
  }

  it('missing workspace/repo/sha skips the Bitbucket call — not a scan failure', async () => {
    const fetchMock = stubFetch();
    process.env.BITBUCKET_TOKEN = 'bb-test';
    const { prisma, tx } = prismaForScan({
      scan: scanRow({ options: { bitbucket: { workspace: WORKSPACE, repoSlug: REPO } } }),
    });
    await expect(
      new BitbucketBuildStatusPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID),
    ).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(tx.scan.update).not.toHaveBeenCalled();
  });

  it('fail_build match → FAILED on api.bitbucket.org', async () => {
    process.env.BITBUCKET_TOKEN = 'bb-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [
        {
          enabled: true,
          priority: 10,
          condition: { severityAtLeast: 'high' },
          actions: ['fail_build'],
        },
      ],
    });
    await new BitbucketBuildStatusPublisher(prisma as never).publishForCompletedScan(
      ORG_A,
      SCAN_ID,
    );
    const post = fetchMock.mock.calls.find(
      (call) => (call[1] as { method?: string })?.method === 'POST',
    );
    expect(post).toBeTruthy();
    expect(String(post![0])).toBe(STATUS_URL);
    const headers = (post![1] as { headers?: Record<string, string> }).headers;
    expect(headers?.authorization).toBe('Bearer bb-test');
    const body = JSON.parse(String((post![1] as { body: string }).body)) as {
      state: string;
      key: string;
      name: string;
    };
    expect(body.state).toBe('FAILED');
    expect(body.key).toBe(`ctem-scan-${SCAN_ID}`);
    expect(body.name).toBe('CTEM');
  });

  it('matching block_deploy does not fail the Bitbucket status — statuses stay on concludeScan', async () => {
    process.env.BITBUCKET_TOKEN = 'bb-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [
        {
          enabled: true,
          priority: 10,
          condition: { severityAtLeast: 'high' },
          actions: ['block_deploy'],
        },
      ],
    });
    await new BitbucketBuildStatusPublisher(prisma as never).publishForCompletedScan(
      ORG_A,
      SCAN_ID,
    );
    expect(postBodies(fetchMock)[0]?.state).toBe('SUCCESSFUL');
  });

  it('no matching fail_build → SUCCESSFUL', async () => {
    process.env.BITBUCKET_TOKEN = 'bb-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow(),
      findings: [matchingFinding],
      policies: [
        { enabled: true, priority: 10, condition: { kevOnly: true }, actions: ['notify'] },
      ],
    });
    await new BitbucketBuildStatusPublisher(prisma as never).publishForCompletedScan(
      ORG_A,
      SCAN_ID,
    );
    expect(postBodies(fetchMock)[0]?.state).toBe('SUCCESSFUL');
  });

  it('ignores client-supplied bitbucket.conclusion and still uses concludeScan', async () => {
    process.env.BITBUCKET_TOKEN = 'bb-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        options: bitbucketOptions({ conclusion: 'failed', state: 'FAILED' }),
        status: 'succeeded',
      }),
      findings: [matchingFinding],
      policies: [
        { enabled: true, priority: 10, condition: { kevOnly: true }, actions: ['notify'] },
      ],
    });
    await new BitbucketBuildStatusPublisher(prisma as never).publishForCompletedScan(
      ORG_A,
      SCAN_ID,
    );
    expect(postBodies(fetchMock)[0]?.state).toBe('SUCCESSFUL');
  });

  it('POSTs only to api.bitbucket.org when the scan names a Server host', async () => {
    process.env.BITBUCKET_TOKEN = 'bb-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        options: bitbucketOptions({
          apiUrl: 'https://bitbucket.example.com',
          baseUrl: 'https://bitbucket.internal',
          bitbucketHost: 'bitbucket.internal',
        }),
        jobs: [
          {
            assetId: ASSET_A,
            findingCount: 0,
            asset: {
              integration: bitbucketIntegration({
                config: {
                  workspace: WORKSPACE,
                  baseUrl: 'https://bitbucket.internal',
                  bitbucketHost: 'bitbucket.internal',
                },
              }),
            },
          },
        ],
      }),
      findings: [],
      policies: [],
    });
    await new BitbucketBuildStatusPublisher(prisma as never).publishForCompletedScan(
      ORG_A,
      SCAN_ID,
    );
    expect(fetchMock.mock.calls.length).toBeGreaterThan(0);
    for (const call of fetchMock.mock.calls) {
      const parsed = new URL(String(call[0]));
      expect(parsed.hostname).toBe(BITBUCKET_API_HOST);
      expect(parsed.protocol).toBe('https:');
      expect(String(call[0])).not.toContain('bitbucket.internal');
      expect(String(call[0])).not.toContain('bitbucket.example.com');
    }
  });

  it('same scanId does not create unbounded distinct keys', async () => {
    process.env.BITBUCKET_TOKEN = 'bb-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [
          { assetId: ASSET_A, findingCount: 0, asset: { integration: bitbucketIntegration() } },
        ],
      }),
      findings: [],
      policies: [],
    });
    const publisher = new BitbucketBuildStatusPublisher(prisma as never);
    await publisher.publishForCompletedScan(ORG_A, SCAN_ID);
    await publisher.publishForCompletedScan(ORG_A, SCAN_ID);
    const bodies = postBodies(fetchMock);
    expect(bodies).toHaveLength(2);
    expect(bodies.map((body) => body.key)).toEqual([
      `ctem-scan-${SCAN_ID}`,
      `ctem-scan-${SCAN_ID}`,
    ]);
    expect(new Set(bodies.map((body) => body.key)).size).toBe(1);
  });

  it('soft-fails a Bitbucket API error without throwing to the lifecycle caller', async () => {
    process.env.BITBUCKET_TOKEN = 'bb-test';
    stubFetch({ postStatus: 502 });
    const { prisma, tx } = prismaForScan({
      scan: scanRow({
        jobs: [
          { assetId: ASSET_A, findingCount: 0, asset: { integration: bitbucketIntegration() } },
        ],
      }),
      findings: [],
      policies: [],
    });
    await expect(
      new BitbucketBuildStatusPublisher(prisma as never).publishForCompletedScan(ORG_A, SCAN_ID),
    ).resolves.toBeUndefined();
    expect(tx.scan.update).not.toHaveBeenCalled();
  });

  it('skips when BITBUCKET_* credentials are unusable — fail closed, no fetch', async () => {
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({
        jobs: [
          { assetId: ASSET_A, findingCount: 0, asset: { integration: bitbucketIntegration() } },
        ],
      }),
    });
    await new BitbucketBuildStatusPublisher(prisma as never).publishForCompletedScan(
      ORG_A,
      SCAN_ID,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('skips a pending concludeScan and does not publish INPROGRESS', async () => {
    process.env.BITBUCKET_TOKEN = 'bb-test';
    const fetchMock = stubFetch();
    const { prisma } = prismaForScan({
      scan: scanRow({ status: 'running' }),
    });
    await new BitbucketBuildStatusPublisher(prisma as never).publishForCompletedScan(
      ORG_A,
      SCAN_ID,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('publishBitbucketBuildStatus never leaves api.bitbucket.org', () => {
  it('POSTs only to https://api.bitbucket.org even if scan options name another host', async () => {
    const urls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        urls.push(String(url));
        return new Response(JSON.stringify({ key: `ctem-scan-${SCAN_ID}` }), { status: 201 });
      }),
    );
    const ctx = parseBitbucketStatusesContext(
      bitbucketOptions({
        apiUrl: 'https://bitbucket.example.com',
        bitbucketHost: 'bitbucket.internal',
      }),
      SCAN_ID,
    )!;
    await publishBitbucketBuildStatus({
      ctx,
      scanId: SCAN_ID,
      state: 'SUCCESSFUL',
      token: 'bb-test',
    });
    expect(urls).toEqual([STATUS_URL]);
    expect(urls[0]).toMatch(/^https:\/\/api\.bitbucket\.org\/2\.0\/repositories\//);
  });
});

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name === 'node_modules' || name === 'dist') continue;
      out.push(...tsFiles(path));
      continue;
    }
    if (name.endsWith('.ts')) out.push(path);
  }
  return out;
}

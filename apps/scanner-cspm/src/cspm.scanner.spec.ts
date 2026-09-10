import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ScanContext } from '@ctem/scanner-sdk';
import { FindingNormalizer } from '../../findings-service/src/findings/finding-normalizer';
import { CSPM_MAX_PAGES, CspmScanError } from './cloud.fetch';
import { CspmCredentialError } from './credentials';
import { AwsEgressError } from './aws.egress';
import { CspmScanner } from './cspm.scanner';
import { POSTURE_RULES } from './posture.rules';

const ACCOUNT = '123456789012';
const REGION = 'us-east-1';
const BUCKET = 'logs-bucket';
const SG = 'sg-0123456789abcdef0';
const gcpPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

function ctx(
  overrides: Partial<ScanContext['job']> = {},
  checkDeadline: () => boolean = () => true,
): ScanContext {
  return {
    job: {
      jobId: randomUUID(),
      scanId: randomUUID(),
      orgId: randomUUID(),
      scannerType: 'cloud_posture',
      assetId: randomUUID(),
      target: {
        kind: 'cloud_resource',
        externalKey: `aws:${ACCOUNT}:s3:${BUCKET}`,
        resourceType: 's3_bucket',
        accountId: ACCOUNT,
        region: REGION,
        arn: `arn:aws:s3:::${BUCKET}`,
      },
      credentialRef: 'env:AWS_ACCESS_KEY_ID',
      options: {},
      attempt: 1,
      deadlineAt: new Date(Date.now() + 60_000),
      traceId: 'test',
      ...overrides,
    },
    workDir: '/tmp',
    checkDeadline,
    log: () => undefined,
  };
}

function awsEnv(): void {
  process.env.AWS_ACCESS_KEY_ID = 'AKIATEST';
  process.env.AWS_SECRET_ACCESS_KEY = 'secret';
}

function xml(body: string): string {
  return `<?xml version="1.0"?>${body}`;
}

function pabXml(blocked: boolean): string {
  const v = blocked ? 'true' : 'false';
  return xml(
    `<PublicAccessBlockConfiguration>
      <BlockPublicAcls>${v}</BlockPublicAcls>
      <BlockPublicPolicy>${v}</BlockPublicPolicy>
      <IgnorePublicAcls>${v}</IgnorePublicAcls>
      <RestrictPublicBuckets>${v}</RestrictPublicBuckets>
    </PublicAccessBlockConfiguration>`,
  );
}

function policyStatusXml(isPublic: boolean): string {
  return xml(`<PolicyStatus><IsPublic>${isPublic ? 'true' : 'false'}</IsPublic></PolicyStatus>`);
}

function aclXml(opts: { public?: boolean; truncated?: boolean; marker?: string }): string {
  const grant = opts.public
    ? `<Grant><Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant>`
    : `<Grant><Grantee><ID>owner</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>`;
  return xml(
    `<AccessControlPolicy><AccessControlList>${grant}</AccessControlList>
    <IsTruncated>${opts.truncated ? 'true' : 'false'}</IsTruncated>
    ${opts.marker ? `<NextToken>${opts.marker}</NextToken>` : ''}
    </AccessControlPolicy>`,
  );
}

function sgXml(open: boolean, next?: string): string {
  const cidr = open ? '0.0.0.0/0' : '10.0.0.0/8';
  return xml(
    `<DescribeSecurityGroupsResponse><securityGroupInfo>
      <item><groupId>${SG}</groupId><ipPermissions><item><ipRanges><item><cidrIp>${cidr}</cidrIp></item></ipRanges></item></ipPermissions></item>
    </securityGroupInfo>${next ? `<nextToken>${next}</nextToken>` : ''}</DescribeSecurityGroupsResponse>`,
  );
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/xml' } });
}

function mockFetch(handler: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  return vi.fn(async (url: string | URL, init?: RequestInit) => handler(String(url), init));
}

afterEach(() => {
  delete process.env.AWS_ACCESS_KEY_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  delete process.env.AWS_SESSION_TOKEN;
  delete process.env.GCP_CLIENT_EMAIL;
  delete process.env.GCP_PRIVATE_KEY;
  delete process.env.AZURE_TENANT_ID;
  delete process.env.AZURE_CLIENT_ID;
  delete process.env.AZURE_CLIENT_SECRET;
});

describe('CspmScanner.supports', () => {
  it('supports cloud_resource only — not kubernetes_workload', () => {
    const s = new CspmScanner();
    expect(s.supports({ target: { kind: 'cloud_resource' } } as never)).toBe(true);
    expect(s.supports({ target: { kind: 'kubernetes_workload' } } as never)).toBe(false);
    expect(s.supports({ target: { kind: 'repository' } } as never)).toBe(false);
  });
});

describe('CspmScanner.execute', () => {
  it('throws for kubernetes_workload instead of returning { findings: [] }', async () => {
    const fetchFn = mockFetch(() => textResponse(''));
    const s = new CspmScanner().useFetch(fetchFn);
    await expect(
      s.execute(ctx({ target: { kind: 'kubernetes_workload', externalKey: 'k8s:ns/deploy' } })),
    ).rejects.toThrow(CspmScanError);
    await expect(
      s.execute(ctx({ target: { kind: 'kubernetes_workload', externalKey: 'k8s:ns/deploy' } })),
    ).rejects.toThrow(/kubernetes_workload/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('fails closed when AWS credentials are missing', async () => {
    const fetchFn = mockFetch(() => textResponse(''));
    const s = new CspmScanner().useFetch(fetchFn);
    await expect(s.execute(ctx())).rejects.toThrow(CspmCredentialError);
    await expect(s.execute(ctx())).rejects.toThrow(/env:AWS_/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('refuses a tenant-writable endpoint before connect', async () => {
    awsEnv();
    const fetchFn = mockFetch(() => textResponse(''));
    const s = new CspmScanner().useFetch(fetchFn);
    await expect(s.execute(ctx({ options: { endpoint: 'https://evil.example' } }))).rejects.toThrow(
      AwsEgressError,
    );
    await expect(s.execute(ctx({ options: { apiUrl: 'https://evil.example/aws' } }))).rejects.toThrow(
      /tenant-writable/,
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('emits a public-bucket finding with unknown reachability', async () => {
    awsEnv();
    const fetchFn = mockFetch((url) => {
      if (url.includes('publicAccessBlock')) return textResponse(pabXml(false));
      if (url.includes('policyStatus')) return textResponse(policyStatusXml(true));
      if (url.includes('acl')) return textResponse(aclXml({ public: false }));
      throw new Error(`unexpected ${url}`);
    });
    const outcome = await new CspmScanner().useFetch(fetchFn).execute(ctx());
    expect(outcome.findings).toHaveLength(1);
    expect(outcome.findings[0]?.identifiers[0]?.value).toBe(POSTURE_RULES.publicBucket.id);
    expect(outcome.findings[0]?.location.resource).toBe(`arn:aws:s3:::${BUCKET}`);
    expect(outcome.findings[0]?.evidence.reachability).toBe('unknown');
    expect(outcome.findings[0]?.scannerType).toBe('cloud_posture');
  });

  it('emits an open-SG finding from live DescribeSecurityGroups', async () => {
    awsEnv();
    const fetchFn = mockFetch((url, init) => {
      const body = String(init?.body ?? '');
      expect(body).toContain('DescribeSecurityGroups');
      expect(body).not.toMatch(/Put|Delete|Create|Authorize|Revoke/i);
      return textResponse(sgXml(true));
    });
    const outcome = await new CspmScanner().useFetch(fetchFn).execute(
      ctx({
        target: {
          kind: 'cloud_resource',
          externalKey: `aws:${ACCOUNT}:sg:${REGION}:${SG}`,
          resourceType: 'security_group',
          accountId: ACCOUNT,
          region: REGION,
          groupId: SG,
          arn: `arn:aws:ec2:${REGION}:${ACCOUNT}:security-group/${SG}`,
        },
      }),
    );
    expect(outcome.findings).toHaveLength(1);
    expect(outcome.findings[0]?.identifiers[0]?.value).toBe(POSTURE_RULES.openSg.id);
    expect(outcome.findings[0]?.evidence.reachability).toBe('unknown');
  });

  it('fails the job on an incomplete API page (truncated without next)', async () => {
    awsEnv();
    const fetchFn = mockFetch((url) => {
      if (url.includes('publicAccessBlock')) return textResponse(pabXml(false));
      if (url.includes('policyStatus')) return textResponse(policyStatusXml(false));
      if (url.includes('acl')) return textResponse(aclXml({ public: true, truncated: true }));
      throw new Error(`unexpected ${url}`);
    });
    await expect(new CspmScanner().useFetch(fetchFn).execute(ctx())).rejects.toThrow(/Incomplete/);
  });

  it('fails the job when a leftover next token remains at the page cap', async () => {
    awsEnv();
    let aclPages = 0;
    const fetchFn = mockFetch((url) => {
      if (url.includes('publicAccessBlock')) return textResponse(pabXml(false));
      if (url.includes('policyStatus')) return textResponse(policyStatusXml(false));
      if (url.includes('acl')) {
        aclPages += 1;
        return textResponse(aclXml({ public: false, truncated: true, marker: `more-${aclPages}` }));
      }
      throw new Error(`unexpected ${url}`);
    });
    await expect(new CspmScanner().useFetch(fetchFn).execute(ctx())).rejects.toThrow(/truncated/);
    expect(aclPages).toBe(CSPM_MAX_PAGES);
  });

  it('does not collide cloud_posture fingerprints with IaC (rule + resource)', async () => {
    awsEnv();
    const fetchFn = mockFetch((url) => {
      if (url.includes('publicAccessBlock')) return textResponse(pabXml(false));
      if (url.includes('policyStatus')) return textResponse(policyStatusXml(true));
      if (url.includes('acl')) return textResponse(aclXml({ public: false }));
      throw new Error(`unexpected ${url}`);
    });
    const outcome = await new CspmScanner().useFetch(fetchFn).execute(ctx());
    const finding = outcome.findings[0]!;
    const normalizer = new FindingNormalizer();
    const cspmFp = normalizer.fingerprint('asset-1', finding);
    expect(cspmFp).toBe(
      createHash('sha256')
        .update(['asset-1', 'cloud_posture', POSTURE_RULES.publicBucket.id, `arn:aws:s3:::${BUCKET}`].join('|'))
        .digest('hex'),
    );
    const iacFp = normalizer.fingerprint('asset-1', {
      ...finding,
      scannerType: 'iac',
      identifiers: [{ system: 'rule', value: 'ctem.iac.s3-public' }],
      location: { path: 's3.tf', resource: finding.location.resource },
    });
    expect(cspmFp).not.toBe(iacFp);
  });

  it('never issues mutating cloud API calls', async () => {
    awsEnv();
    const fetchFn = mockFetch((url) => {
      if (url.includes('publicAccessBlock')) return textResponse(pabXml(true));
      if (url.includes('policyStatus')) return textResponse(policyStatusXml(false));
      if (url.includes('acl')) return textResponse(aclXml({ public: false }));
      throw new Error(`unexpected ${url}`);
    });
    const scanner = new CspmScanner().useFetch(fetchFn);
    await scanner.execute(ctx());
    for (const [, init] of fetchFn.mock.calls) {
      const method = String(init?.method ?? 'GET').toUpperCase();
      expect(['GET', 'POST']).toContain(method);
      const body = String(init?.body ?? '');
      expect(body).not.toMatch(/Put|Delete|Create|Modify|Authorize|Revoke|Update/i);
    }
    expect(fetchFn.mock.calls.every(([url]) => String(url).includes('amazonaws.com'))).toBe(true);
  });

  it('evaluates a public GCS bucket via allowlisted googleapis.com IAM GET', async () => {
    process.env.GCP_CLIENT_EMAIL = 'ctem@acme-prod.iam.gserviceaccount.com';
    process.env.GCP_PRIVATE_KEY = gcpPem;
    const fetchFn = mockFetch((url) => {
      if (url.includes('oauth2.googleapis.com')) {
        return jsonResponse({ access_token: 'ya29.token' });
      }
      if (url.includes('/iam')) {
        return jsonResponse({
          bindings: [{ role: 'roles/storage.objectViewer', members: ['allUsers'] }],
        });
      }
      if (url.includes('/storage/v1/b/')) {
        return jsonResponse({ iamConfiguration: { publicAccessPrevention: 'inherited' } });
      }
      throw new Error(`unexpected ${url}`);
    });
    const outcome = await new CspmScanner().useFetch(fetchFn).execute(
      ctx({
        credentialRef: 'env:GCP_CLIENT_EMAIL',
        target: {
          kind: 'cloud_resource',
          externalKey: 'gcp:acme-prod:gcs:logs-bucket',
          resourceType: 'gcs_bucket',
          projectId: 'acme-prod',
        },
      }),
    );
    expect(outcome.findings).toHaveLength(1);
    expect(outcome.findings[0]?.identifiers[0]?.value).toBe(POSTURE_RULES.publicBucket.id);
    expect(fetchFn.mock.calls.every(([url]) => String(url).includes('googleapis.com'))).toBe(true);
  });
});

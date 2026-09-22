import { describe, expect, it } from 'vitest';
import {
  CreatePolicyRequest,
  CreateScanRequest,
  IngestSbomRequest,
  SCAN_KICK_EVENT,
  Scan,
  ScanKickMeterRecord,
  UpdatePolicyRequest,
  EVENT_SCHEMAS,
  InviteMemberRequest,
  ResolveJwtRequest,
  ResolveJwtResponse,
  ROLE_PERMISSIONS,
  SUBJECTS,
  STREAMS,
  ScanJob,
  SetMemberRoleRequest,
  concludeDeploy,
  concludeScan,
  findClientConclusionKeys,
  findTenantWebhookKeys,
  matchesPolicyCondition,
  promoteScaValidation,
} from './index';

describe('event catalog', () => {
  it('has a payload schema for every subject', () => {
    for (const subject of Object.values(SUBJECTS)) {
      expect(EVENT_SCHEMAS[subject], `missing schema for ${subject}`).toBeDefined();
    }
  });

  it('routes every subject to exactly one stream', () => {
    for (const subject of Object.values(SUBJECTS)) {
      const matches = Object.values(STREAMS).filter((s) =>
        s.subjects.some((p) => (p.endsWith('>') ? subject.startsWith(p.slice(0, -1)) : subject === p)),
      );
      expect(matches, `${subject} matched ${matches.length} streams`).toHaveLength(1);
    }
  });
});

describe('scan job contract', () => {
  it('rejects a job without tenancy', () => {
    expect(() =>
      ScanJob.parse({
        jobId: '00000000-0000-4000-8000-000000000001',
        scanId: '00000000-0000-4000-8000-000000000002',
        scannerType: 'sca',
        assetId: '00000000-0000-4000-8000-000000000003',
        target: {},
        deadlineAt: new Date(),
        traceId: 't',
      }),
    ).toThrow();
  });
});

describe('rbac', () => {
  it('never grants an auditor a write permission', () => {
    expect(ROLE_PERMISSIONS.auditor.some((p) => p.endsWith(':write'))).toBe(false);
    expect(ROLE_PERMISSIONS.auditor).not.toContain('finding:triage');
  });

  it('gives the owner everything', () => {
    expect(ROLE_PERMISSIONS.owner).toContain('org:write');
    expect(ROLE_PERMISSIONS.owner).toContain('exception:approve');
    expect(ROLE_PERMISSIONS.admin).toContain('member:manage');
    expect(ROLE_PERMISSIONS.admin).not.toContain('org:write');
  });

  it('rejects invalid member admin payloads as 4xx-shaped zod errors, not 500', () => {
    expect(InviteMemberRequest.safeParse({ email: 'not-an-email', role: 'developer' }).success).toBe(
      false,
    );
    expect(InviteMemberRequest.safeParse({ email: 'ok@test.local', role: 'superuser' }).success).toBe(
      false,
    );
    expect(SetMemberRoleRequest.safeParse({ role: 'superuser' }).success).toBe(false);
    expect(SetMemberRoleRequest.safeParse({}).success).toBe(false);
    expect(ResolveJwtRequest.safeParse({ sub: 'idp|alice', orgId: 'not-a-uuid' }).success).toBe(
      false,
    );
    expect(
      ResolveJwtResponse.safeParse({
        userId: 'idp|alice',
        orgId: 'c7e00000-0000-4000-8000-000000000001',
        role: 'owner',
      }).success,
    ).toBe(false);
  });
});

describe('policy editor writes', () => {
  const notifyRule = {
    name: 'KEV notify',
    condition: { kevOnly: true },
    actions: ['notify'],
  };

  it('accepts notify, ticket, fail_build, or block_deploy create and update, persisting priority', () => {
    expect(CreatePolicyRequest.parse({ ...notifyRule, priority: 10 })).toMatchObject({
      actions: ['notify'],
      priority: 10,
    });
    expect(CreatePolicyRequest.parse({ ...notifyRule, actions: ['ticket'] })).toMatchObject({
      actions: ['ticket'],
    });
    expect(CreatePolicyRequest.parse({ ...notifyRule, actions: ['fail_build'] })).toMatchObject({
      actions: ['fail_build'],
    });
    expect(CreatePolicyRequest.parse({ ...notifyRule, actions: ['block_deploy'] })).toMatchObject({
      actions: ['block_deploy'],
    });
    expect(
      CreatePolicyRequest.parse({ ...notifyRule, actions: ['notify', 'ticket'] }),
    ).toMatchObject({ actions: ['notify', 'ticket'] });
    expect(
      CreatePolicyRequest.parse({ ...notifyRule, actions: ['notify', 'fail_build'] }),
    ).toMatchObject({ actions: ['notify', 'fail_build'] });
    expect(
      CreatePolicyRequest.parse({ ...notifyRule, actions: ['notify', 'block_deploy'] }),
    ).toMatchObject({ actions: ['notify', 'block_deploy'] });
    expect(
      CreatePolicyRequest.parse({
        ...notifyRule,
        actions: ['notify', 'ticket', 'fail_build', 'block_deploy'],
      }),
    ).toMatchObject({ actions: ['notify', 'ticket', 'fail_build', 'block_deploy'] });
    expect(UpdatePolicyRequest.parse({ priority: 5 })).toEqual({ priority: 5 });
    expect(UpdatePolicyRequest.parse({ actions: ['ticket'] })).toEqual({ actions: ['ticket'] });
    expect(UpdatePolicyRequest.parse({ actions: ['fail_build'] })).toEqual({ actions: ['fail_build'] });
    expect(UpdatePolicyRequest.parse({ actions: ['block_deploy'] })).toEqual({
      actions: ['block_deploy'],
    });
    expect(UpdatePolicyRequest.parse({ actions: ['ticket', 'block_deploy'] })).toEqual({
      actions: ['ticket', 'block_deploy'],
    });
  });

  it('keeps ignore off the editor', () => {
    expect(() => CreatePolicyRequest.parse({ ...notifyRule, actions: ['ignore'] })).toThrow();
    expect(() => UpdatePolicyRequest.parse({ actions: ['ignore'] })).toThrow();
    expect(() => UpdatePolicyRequest.parse({ actions: [] })).toThrow();
  });

  it('refuses a tenant webhook URL if it appears', () => {
    expect(findTenantWebhookKeys({ ...notifyRule, webhookUrl: 'https://evil.test/hook' })).toEqual([
      'webhookUrl',
    ]);
    expect(
      findTenantWebhookKeys({ condition: { webhookUrl: 'https://attacker.test/x' } }),
    ).toEqual(['condition.webhookUrl']);
    expect(() =>
      CreatePolicyRequest.parse({ ...notifyRule, webhookUrl: 'https://evil.test/hook' }),
    ).toThrow();
    expect(findTenantWebhookKeys({ ...notifyRule, jiraUrl: 'https://evil.test/jira' })).toEqual([
      'jiraUrl',
    ]);
  });
});

const finding = {
  id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  severity: 'high',
  riskScore: 80,
  kev: false,
  epssScore: 0.2,
  fixAvailable: true,
  scannerType: 'sca',
  asset: { kind: 'repository', exposure: 'internal', criticality: 'tier2', tags: {} },
};

describe('scan conclusion', () => {
  it('fails only when a matching fail_build rule wins', () => {
    expect(
      concludeScan({
        status: 'succeeded',
        findings: [finding],
        policies: [
          {
            priority: 10,
            condition: { severityAtLeast: 'high' },
            actions: ['fail_build'],
          },
        ],
        expectedFindingCount: 1,
      }),
    ).toBe('failed');
  });

  it('stays passed when no fail_build rule matches — a client conclusion cannot force failed', () => {
    const forced = {
      status: 'succeeded',
      findings: [finding],
      policies: [{ priority: 10, condition: { kevOnly: true }, actions: ['notify'] }],
      expectedFindingCount: 1,
      // Callers might try to smuggle this. concludeScan has no such argument.
      clientConclusion: 'failed',
    };
    expect(concludeScan(forced)).toBe('passed');
    expect(
      concludeScan({
        status: 'succeeded',
        findings: [finding],
        policies: [
          { priority: 10, condition: { severityAtLeast: 'high' }, actions: ['notify'] },
          { priority: 20, condition: {}, actions: ['fail_build'] },
        ],
        expectedFindingCount: 1,
      }),
    ).toBe('passed');
  });

  it('is pending while the scan is running', () => {
    expect(
      concludeScan({
        status: 'running',
        findings: [finding],
        policies: [{ priority: 1, condition: {}, actions: ['fail_build'] }],
      }),
    ).toBe('pending');
  });

  it('does not fail conclusion from a matching block_deploy rule', () => {
    expect(
      concludeScan({
        status: 'succeeded',
        findings: [finding],
        policies: [
          {
            priority: 10,
            condition: { severityAtLeast: 'high' },
            actions: ['block_deploy'],
          },
        ],
        expectedFindingCount: 1,
      }),
    ).toBe('passed');
  });
});

describe('deploy conclusion', () => {
  it('blocks only when a matching block_deploy rule wins', () => {
    expect(
      concludeDeploy({
        status: 'succeeded',
        findings: [finding],
        policies: [
          {
            priority: 10,
            condition: { severityAtLeast: 'high' },
            actions: ['block_deploy'],
          },
        ],
        expectedFindingCount: 1,
      }),
    ).toBe('blocked');
  });

  it('stays allowed when only fail_build matches — gates are independent', () => {
    expect(
      concludeDeploy({
        status: 'succeeded',
        findings: [finding],
        policies: [
          {
            priority: 10,
            condition: { severityAtLeast: 'high' },
            actions: ['fail_build'],
          },
        ],
        expectedFindingCount: 1,
      }),
    ).toBe('allowed');
  });

  it('stays allowed when no block_deploy rule matches — a client field cannot force blocked', () => {
    const forced = {
      status: 'succeeded',
      findings: [finding],
      policies: [{ priority: 10, condition: { kevOnly: true }, actions: ['notify'] }],
      expectedFindingCount: 1,
      clientDeployConclusion: 'blocked',
    };
    expect(concludeDeploy(forced)).toBe('allowed');
    expect(
      concludeDeploy({
        status: 'succeeded',
        findings: [finding],
        policies: [
          { priority: 10, condition: { severityAtLeast: 'high' }, actions: ['notify'] },
          { priority: 20, condition: {}, actions: ['block_deploy'] },
        ],
        expectedFindingCount: 1,
      }),
    ).toBe('allowed');
  });

  it('is pending while the scan is running or findings are still expected', () => {
    expect(
      concludeDeploy({
        status: 'running',
        findings: [finding],
        policies: [{ priority: 1, condition: {}, actions: ['block_deploy'] }],
      }),
    ).toBe('pending');
    expect(
      concludeDeploy({
        status: 'queued',
        findings: [],
        policies: [{ priority: 1, condition: {}, actions: ['block_deploy'] }],
      }),
    ).toBe('pending');
    expect(
      concludeDeploy({
        status: 'succeeded',
        findings: [],
        policies: [{ priority: 1, condition: {}, actions: ['block_deploy'] }],
        expectedFindingCount: 1,
      }),
    ).toBe('pending');
  });

  it('blocks when the first matching policy includes block_deploy among other actions', () => {
    expect(
      concludeDeploy({
        status: 'succeeded',
        findings: [finding],
        policies: [
          {
            priority: 10,
            condition: { severityAtLeast: 'high' },
            actions: ['notify', 'fail_build', 'block_deploy'],
          },
        ],
        expectedFindingCount: 1,
      }),
    ).toBe('blocked');
    expect(
      concludeScan({
        status: 'succeeded',
        findings: [finding],
        policies: [
          {
            priority: 10,
            condition: { severityAtLeast: 'high' },
            actions: ['notify', 'fail_build', 'block_deploy'],
          },
        ],
        expectedFindingCount: 1,
      }),
    ).toBe('failed');
  });
});

describe('matchesPolicyCondition', () => {
  it('matches an empty condition and respects severityAtLeast', () => {
    expect(matchesPolicyCondition({}, finding)).toBe(true);
    expect(matchesPolicyCondition({ severityAtLeast: 'critical' }, finding)).toBe(false);
  });
});

describe('client cannot write scan conclusion', () => {
  it('refuses conclusion on create and nested under options', () => {
    expect(findClientConclusionKeys({ scannerType: 'sca', conclusion: 'failed' })).toEqual([
      'conclusion',
    ]);
    expect(
      findClientConclusionKeys({ scannerType: 'sca', options: { conclusion: 'failed' } }),
    ).toEqual(['options.conclusion']);
    expect(() =>
      CreateScanRequest.parse({ scannerType: 'sca', conclusion: 'failed' }),
    ).toThrow();
    expect(() =>
      CreateScanRequest.parse({ scannerType: 'sca', options: { conclusion: 'failed' } }),
    ).toThrow(/not client-writable/);
    expect(CreateScanRequest.parse({ scannerType: 'sca' })).toMatchObject({
      scannerType: 'sca',
    });
  });

  it('refuses client-written deployConclusion on create and nested under options', () => {
    expect(
      findClientConclusionKeys({ scannerType: 'sca', deployConclusion: 'blocked' }),
    ).toEqual(['deployConclusion']);
    expect(
      findClientConclusionKeys({ scannerType: 'sca', options: { deployConclusion: 'blocked' } }),
    ).toEqual(['options.deployConclusion']);
    expect(() =>
      CreateScanRequest.parse({ scannerType: 'sca', deployConclusion: 'blocked' }),
    ).toThrow();
    expect(() =>
      CreateScanRequest.parse({ scannerType: 'sca', options: { deployConclusion: 'blocked' } }),
    ).toThrow(/not client-writable/);
    expect(() =>
      CreateScanRequest.parse({ scannerType: 'sca', options: { deploy_conclusion: 'blocked' } }),
    ).toThrow(/not client-writable/);
    expect(CreateScanRequest.parse({ scannerType: 'sca' })).not.toHaveProperty('deployConclusion');
  });

  it('accepts deployConclusion on the GET Scan shape only', () => {
    const base = {
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      orgId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      scannerType: 'sca' as const,
      trigger: 'ci' as const,
      status: 'succeeded' as const,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    expect(Scan.parse({ ...base, conclusion: 'failed', deployConclusion: 'blocked' })).toMatchObject({
      conclusion: 'failed',
      deployConclusion: 'blocked',
    });
    expect(Scan.parse({ ...base, deployConclusion: 'allowed' }).deployConclusion).toBe('allowed');
    expect(Scan.parse({ ...base, deployConclusion: 'pending' }).deployConclusion).toBe('pending');
    expect(() => Scan.parse({ ...base, deployConclusion: 'failed' })).toThrow();
  });
});

describe('promoteScaValidation', () => {
  it.each([
    {
      name: 'reachable + KEV → exploitable',
      scannerType: 'sca',
      evidence: { reachability: 'reachable' },
      kev: true,
      expected: 'exploitable',
    },
    {
      name: 'reachable alone → reachable',
      scannerType: 'sca',
      evidence: { reachability: 'reachable' },
      kev: false,
      expected: 'reachable',
    },
    {
      name: 'not_reachable → not_reachable (KEV does not override)',
      scannerType: 'sca',
      evidence: { reachability: 'not_reachable' },
      kev: true,
      expected: 'not_reachable',
    },
    {
      name: 'unknown → leave prior / default',
      scannerType: 'sca',
      evidence: { reachability: 'unknown' },
      kev: true,
      expected: undefined,
    },
    {
      name: 'missing reachability → leave prior / default',
      scannerType: 'sca',
      evidence: {},
      kev: true,
      expected: undefined,
    },
    {
      name: 'non-string reachability → leave prior / default',
      scannerType: 'sca',
      evidence: { reachability: true },
      kev: true,
      expected: undefined,
    },
    {
      name: 'SAST reachable does not promote',
      scannerType: 'sast',
      evidence: { reachability: 'reachable' },
      kev: true,
      expected: undefined,
    },
    {
      name: 'ASM reachable does not promote',
      scannerType: 'asm',
      evidence: { reachability: 'reachable' },
      kev: false,
      expected: undefined,
    },
    {
      name: 'CSPM unknown does not promote',
      scannerType: 'cloud_posture',
      evidence: { reachability: 'unknown' },
      kev: false,
      expected: undefined,
    },
    {
      name: 'container unknown does not promote',
      scannerType: 'container',
      evidence: { reachability: 'unknown' },
      kev: false,
      expected: undefined,
    },
    {
      name: 'IaC unknown does not promote',
      scannerType: 'iac',
      evidence: { reachability: 'unknown' },
      kev: false,
      expected: undefined,
    },
  ] as const)('$name', ({ scannerType, evidence, kev, expected }) => {
    expect(promoteScaValidation({ scannerType, evidence, kev })).toBe(expected);
  });

  it('never returns not_exploitable or compensating_control', () => {
    const verdicts = [
      promoteScaValidation({ scannerType: 'sca', evidence: { reachability: 'reachable' }, kev: true }),
      promoteScaValidation({ scannerType: 'sca', evidence: { reachability: 'reachable' }, kev: false }),
      promoteScaValidation({ scannerType: 'sca', evidence: { reachability: 'not_reachable' }, kev: false }),
      promoteScaValidation({ scannerType: 'sca', evidence: { reachability: 'unknown' }, kev: false }),
    ];
    expect(verdicts).not.toContain('not_exploitable');
    expect(verdicts).not.toContain('compensating_control');
  });
});

describe('scan.kick meter record', () => {
  it('parses the minimal record and accepts CI external_id as externalId', () => {
    const record = ScanKickMeterRecord.parse({
      eventId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      orgId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      scanId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      source: 'schedule',
      scannerTypes: ['sca'],
      occurredAt: '2026-09-22T00:00:00.000Z',
    });
    expect(record.source).toBe('schedule');
    expect(SCAN_KICK_EVENT).toBe('scan.kick');
    expect(CreateScanRequest.parse({ scannerType: 'sca', external_id: 'build-7' }).externalId).toBe('build-7');
    expect(
      IngestSbomRequest.parse({
        assetExternalKey: 'github:acme/api',
        format: 'cyclonedx-json',
        artifactKey: 'sbom/1',
        external_id: 'build-7',
      }).externalId,
    ).toBe('build-7');
  });
});

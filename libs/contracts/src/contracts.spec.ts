import { describe, expect, it } from 'vitest';
import {
  CreatePolicyRequest,
  CreateScanRequest,
  UpdatePolicyRequest,
  EVENT_SCHEMAS,
  ROLE_PERMISSIONS,
  SUBJECTS,
  STREAMS,
  ScanJob,
  concludeScan,
  findClientConclusionKeys,
  findTenantWebhookKeys,
  matchesPolicyCondition,
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
  });
});

describe('policy editor writes', () => {
  const notifyRule = {
    name: 'KEV notify',
    condition: { kevOnly: true },
    actions: ['notify'],
  };

  it('accepts notify, ticket, or fail_build create and update, persisting priority', () => {
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
    expect(
      CreatePolicyRequest.parse({ ...notifyRule, actions: ['notify', 'ticket'] }),
    ).toMatchObject({ actions: ['notify', 'ticket'] });
    expect(
      CreatePolicyRequest.parse({ ...notifyRule, actions: ['notify', 'fail_build'] }),
    ).toMatchObject({ actions: ['notify', 'fail_build'] });
    expect(UpdatePolicyRequest.parse({ priority: 5 })).toEqual({ priority: 5 });
    expect(UpdatePolicyRequest.parse({ actions: ['ticket'] })).toEqual({ actions: ['ticket'] });
    expect(UpdatePolicyRequest.parse({ actions: ['fail_build'] })).toEqual({ actions: ['fail_build'] });
  });

  it('refuses block_deploy on create and update', () => {
    expect(() => UpdatePolicyRequest.parse({ actions: ['block_deploy'] })).toThrow();
    expect(() =>
      CreatePolicyRequest.parse({ ...notifyRule, actions: ['notify', 'block_deploy'] }),
    ).toThrow();
    expect(() => UpdatePolicyRequest.parse({ actions: ['ticket', 'block_deploy'] })).toThrow();
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
});

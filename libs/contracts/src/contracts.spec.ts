import { describe, expect, it } from 'vitest';
import {
  CreatePolicyRequest,
  UpdatePolicyRequest,
  EVENT_SCHEMAS,
  ROLE_PERMISSIONS,
  SUBJECTS,
  STREAMS,
  ScanJob,
  findTenantWebhookKeys,
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

  it('accepts notify or ticket create and update, persisting priority', () => {
    expect(CreatePolicyRequest.parse({ ...notifyRule, priority: 10 })).toMatchObject({
      actions: ['notify'],
      priority: 10,
    });
    expect(CreatePolicyRequest.parse({ ...notifyRule, actions: ['ticket'] })).toMatchObject({
      actions: ['ticket'],
    });
    expect(
      CreatePolicyRequest.parse({ ...notifyRule, actions: ['notify', 'ticket'] }),
    ).toMatchObject({ actions: ['notify', 'ticket'] });
    expect(UpdatePolicyRequest.parse({ priority: 5 })).toEqual({ priority: 5 });
    expect(UpdatePolicyRequest.parse({ actions: ['ticket'] })).toEqual({ actions: ['ticket'] });
  });

  it('refuses fail_build / block_deploy on create and update', () => {
    expect(() =>
      CreatePolicyRequest.parse({ ...notifyRule, actions: ['fail_build'] }),
    ).toThrow();
    expect(() =>
      CreatePolicyRequest.parse({ ...notifyRule, actions: ['notify', 'fail_build'] }),
    ).toThrow();
    expect(() => UpdatePolicyRequest.parse({ actions: ['block_deploy'] })).toThrow();
    expect(() => UpdatePolicyRequest.parse({ actions: ['ticket', 'fail_build'] })).toThrow();
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

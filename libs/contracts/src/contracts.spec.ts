import { describe, expect, it } from 'vitest';
import { EVENT_SCHEMAS, ROLE_PERMISSIONS, SUBJECTS, STREAMS, ScanJob } from './index';

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

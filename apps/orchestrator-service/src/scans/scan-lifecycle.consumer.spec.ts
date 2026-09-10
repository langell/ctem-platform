import { describe, expect, it, vi } from 'vitest';
import { SUBJECTS } from '@ctem/contracts';
import { ScanLifecycleConsumer } from './scan-lifecycle.consumer';
import type { GithubChecksPublisher } from './github-checks.publisher';

const ORG = '4a6f9f4e-1111-4222-8333-444455556666';
const SCAN = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const JOB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

describe('ScanLifecycleConsumer GitHub Checks wiring', () => {
  it('publishes Checks after scanCompleted using the event org, not a client header', async () => {
    const terminal = { id: SCAN, status: 'succeeded', jobsCompleted: 1, jobsTotal: 1 };
    const tx = {
      scanJob: { update: vi.fn(async () => ({})), count: vi.fn(async () => 0) },
      scan: {
        update: vi.fn(async () => terminal),
      },
    };
    const prisma = {
      withOrg: vi.fn(async (orgId: string, fn: (client: typeof tx) => unknown) => {
        expect(orgId).toBe(ORG);
        return fn(tx);
      }),
    };
    const bus = { publish: vi.fn(async () => undefined) };
    const checks = { publishForCompletedScan: vi.fn(async () => undefined) };

    const consumer = new ScanLifecycleConsumer(
      prisma as never,
      bus as never,
      checks as unknown as GithubChecksPublisher,
    );

    await consumer.applyResult({
      jobId: JOB,
      scanId: SCAN,
      orgId: ORG,
      scannerType: 'sca',
      assetId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      status: 'succeeded',
      startedAt: new Date(),
      finishedAt: new Date(),
      artifactKey: null,
      findingCount: 0,
      error: null,
      stats: {},
    });

    expect(bus.publish).toHaveBeenCalledWith(
      SUBJECTS.scanCompleted,
      ORG,
      expect.objectContaining({ scanId: SCAN, status: 'succeeded' }),
    );
    expect(checks.publishForCompletedScan).toHaveBeenCalledWith(ORG, SCAN);
  });

  it('does not publish Checks until the last job completes', async () => {
    const tx = {
      scanJob: { update: vi.fn(async () => ({})) },
      scan: { update: vi.fn(async () => ({ id: SCAN, jobsCompleted: 1, jobsTotal: 2 })) },
    };
    const prisma = {
      withOrg: vi.fn(async (_org: string, fn: (client: typeof tx) => unknown) => fn(tx)),
    };
    const checks = { publishForCompletedScan: vi.fn(async () => undefined) };
    const consumer = new ScanLifecycleConsumer(
      prisma as never,
      { publish: vi.fn() } as never,
      checks as unknown as GithubChecksPublisher,
    );
    await consumer.applyResult({
      jobId: JOB,
      scanId: SCAN,
      orgId: ORG,
      scannerType: 'sca',
      assetId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      status: 'succeeded',
      startedAt: new Date(),
      finishedAt: new Date(),
      artifactKey: null,
      findingCount: 0,
      error: null,
      stats: {},
    });
    expect(checks.publishForCompletedScan).not.toHaveBeenCalled();
  });
});

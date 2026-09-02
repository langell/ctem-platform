import { describe, expect, it, vi } from 'vitest';
import { SUBJECTS } from '@ctem/contracts';
import {
  ScanDispatcherService,
  scanJobCredentialRef,
  scanJobTarget,
} from './scan-dispatcher.service';
import type { ScanPlannerService } from './scan-planner.service';

describe('scanJobTarget', () => {
  it('spreads connector attributes so cloneUrl and private survive dispatch', () => {
    expect(
      scanJobTarget({
        externalKey: 'gitlab:acme/api',
        kind: 'repository',
        attributes: {
          cloneUrl: 'https://gitlab.com/acme/api.git',
          private: true,
          htmlUrl: 'https://gitlab.com/acme/api',
        },
      }),
    ).toEqual({
      externalKey: 'gitlab:acme/api',
      kind: 'repository',
      cloneUrl: 'https://gitlab.com/acme/api.git',
      private: true,
      htmlUrl: 'https://gitlab.com/acme/api',
    });
  });

  it('tolerates a null attributes blob', () => {
    expect(scanJobTarget({ externalKey: 'github:acme/api', kind: 'repository', attributes: null })).toEqual({
      externalKey: 'github:acme/api',
      kind: 'repository',
    });
  });
});

describe('scanJobCredentialRef', () => {
  it('copies the discovering integration pointer and stays null without one', () => {
    const refs = new Map<string, string | null>([['int-gl', 'env:GITLAB_TOKEN']]);
    expect(scanJobCredentialRef({ integrationId: 'int-gl' }, refs)).toBe('env:GITLAB_TOKEN');
    expect(scanJobCredentialRef({ integrationId: null }, refs)).toBeNull();
    expect(scanJobCredentialRef({ integrationId: 'missing' }, refs)).toBeNull();
  });
});

describe('ScanDispatcherService credentialRef wiring', () => {
  const orgId = '11111111-1111-4111-8111-111111111111';
  const assetId = '22222222-2222-4222-8222-222222222222';
  const scanId = '33333333-3333-4333-8333-333333333333';
  const jobId = '44444444-4444-4444-8444-444444444444';
  const integrationId = '55555555-5555-4555-8555-555555555555';

  const gitlabAsset = {
    id: assetId,
    kind: 'repository',
    externalKey: 'gitlab:acme/api',
    attributes: { cloneUrl: 'https://gitlab.com/acme/api.git', private: true },
    integrationId,
  };

  it('publishes the integration credentialRef and attributes on create and retry', async () => {
    const published: Array<{ subject: string; payload: { credentialRef: string | null; target: Record<string, unknown> } }> =
      [];

    const planner = {
      plan: vi.fn(async () => [gitlabAsset]),
    };

    const tx = {
      scan: {
        create: vi.fn(async ({ data }: { data: object }) => ({ id: scanId, ...data })),
      },
      scanJob: {
        createMany: vi.fn(async () => ({ count: 1 })),
        findMany: vi.fn(async () => [
          {
            id: jobId,
            scanId,
            orgId,
            assetId,
            scannerType: 'sca',
            attempt: 1,
          },
        ]),
        update: vi.fn(async () => ({
          id: jobId,
          scanId,
          orgId,
          assetId,
          scannerType: 'sca',
          attempt: 2,
        })),
      },
      asset: {
        findUniqueOrThrow: vi.fn(async () => gitlabAsset),
      },
      integration: {
        findMany: vi.fn(async () => [{ id: integrationId, credentialRef: 'env:GITLAB_TOKEN' }]),
      },
    };

    const prisma = {
      withOrg: vi.fn(async (_org: string, fn: (client: typeof tx) => Promise<unknown>) => fn(tx)),
    };

    const bus = {
      publish: vi.fn(async (subject: string, _org: string, payload: { credentialRef: string | null; target: Record<string, unknown> }) => {
        published.push({ subject, payload });
      }),
    };

    const dispatcher = new ScanDispatcherService(
      prisma as never,
      planner as unknown as ScanPlannerService,
      bus as never,
    );

    await dispatcher.createScan(orgId, null, { scannerType: 'sca', assetSelector: {}, options: {} });

    expect(tx.scan.create).toHaveBeenCalledWith({
      data: expect.not.objectContaining({ conclusion: expect.anything() }),
    });
    expect(published).toHaveLength(1);
    expect(published[0].subject).toBe(SUBJECTS.scanJobDispatched);
    expect(published[0].payload.credentialRef).toBe('env:GITLAB_TOKEN');
    expect(published[0].payload.target).toMatchObject({
      externalKey: 'gitlab:acme/api',
      cloneUrl: 'https://gitlab.com/acme/api.git',
      private: true,
    });
    expect(tx.integration.findMany).toHaveBeenCalled();

    published.length = 0;
    await dispatcher.retryJob(orgId, jobId);
    expect(published).toHaveLength(1);
    expect(published[0].payload.credentialRef).toBe('env:GITLAB_TOKEN');
    expect(published[0].payload.target).toMatchObject({
      externalKey: 'gitlab:acme/api',
      cloneUrl: 'https://gitlab.com/acme/api.git',
    });
  });
});

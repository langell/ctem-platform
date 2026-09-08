import { BadRequestException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { ScanJob, SUBJECTS } from '@ctem/contracts';
import { DEMO_CONTAINER_IMAGE, DEMO_IDP_SUBJECT } from '@ctem/testing';
import {
  ScanDispatcherService,
  requestedByFromPrincipal,
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
          cloneUrl: 'https://gitlab.example.com/acme/api.git',
          gitlabHost: 'gitlab.example.com',
          private: true,
          htmlUrl: 'https://gitlab.example.com/acme/api',
        },
      }),
    ).toEqual({
      externalKey: 'gitlab:acme/api',
      kind: 'repository',
      cloneUrl: 'https://gitlab.example.com/acme/api.git',
      gitlabHost: 'gitlab.example.com',
      private: true,
      htmlUrl: 'https://gitlab.example.com/acme/api',
    });
  });

  it('tolerates a null attributes blob', () => {
    expect(scanJobTarget({ externalKey: 'github:acme/api', kind: 'repository', attributes: null })).toEqual({
      externalKey: 'github:acme/api',
      kind: 'repository',
    });
  });

  it('spreads GHCR digest attributes onto the container job target', () => {
    expect(
      scanJobTarget({
        externalKey: DEMO_CONTAINER_IMAGE.externalKey,
        kind: 'container_image',
        attributes: DEMO_CONTAINER_IMAGE.attributes,
      }),
    ).toMatchObject({
      kind: 'container_image',
      externalKey: DEMO_CONTAINER_IMAGE.externalKey,
      digest: DEMO_CONTAINER_IMAGE.attributes.digest,
      owner: 'demo',
      package: 'payments-api',
    });
  });
});

describe('requestedByFromPrincipal', () => {
  it('classifies a UUID, an IdP subject, and null', () => {
    expect(requestedByFromPrincipal('11111111-1111-4111-8111-111111111111')).toEqual({
      kind: 'uuid',
      id: '11111111-1111-4111-8111-111111111111',
    });
    expect(requestedByFromPrincipal(DEMO_IDP_SUBJECT)).toEqual({ kind: 'idp', subject: DEMO_IDP_SUBJECT });
    expect(requestedByFromPrincipal(null)).toEqual({ kind: 'none' });
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

    const createdScan = { id: scanId, status: 'running', jobsTotal: 1, jobsCompleted: 0 };
    const tx = {
      scan: {
        create: vi.fn(async ({ data }: { data: object }) => ({ id: scanId, ...data })),
        findUnique: vi.fn(async () => createdScan),
        update: vi.fn(async ({ data }: { data: object }) => ({ ...createdScan, ...data })),
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

describe('ScanDispatcherService container kick', () => {
  const orgId = '11111111-1111-4111-8111-111111111111';
  const assetId = '22222222-2222-4222-8222-222222222222';
  const scanId = '33333333-3333-4333-8333-333333333333';
  const jobId = '44444444-4444-4444-8444-444444444444';

  const legacyAsset = {
    id: assetId,
    kind: 'container_image',
    externalKey: 'image:ghcr.io/demo/payments-api:latest',
    attributes: {},
    integrationId: null,
  };

  const digestAsset = {
    id: assetId,
    kind: 'container_image',
    externalKey: DEMO_CONTAINER_IMAGE.externalKey,
    attributes: DEMO_CONTAINER_IMAGE.attributes,
    integrationId: null,
  };

  function harness(asset: typeof legacyAsset, publishImpl?: (subject: string, payload: unknown) => Promise<void>) {
    const createdScan = { id: scanId, status: 'running', jobsTotal: 1, jobsCompleted: 0, scannerType: 'container' };
    const failedJobs: unknown[] = [];
    const tx = {
      scan: {
        create: vi.fn(async ({ data }: { data: object }) => ({ id: scanId, ...data })),
        findUnique: vi.fn(async () => createdScan),
        update: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
          Object.assign(createdScan, data);
          if (typeof data.jobsCompleted === 'object') createdScan.jobsCompleted += 1;
          return createdScan;
        }),
      },
      scanJob: {
        createMany: vi.fn(async () => ({ count: 1 })),
        findMany: vi.fn(async () => [
          { id: jobId, scanId, orgId, assetId, scannerType: 'container', attempt: 1 },
        ]),
        update: vi.fn(async ({ data }: { data: object }) => {
          failedJobs.push(data);
          return { id: jobId, scanId, ...data };
        }),
        count: vi.fn(async () => 1),
      },
      integration: { findMany: vi.fn(async () => []) },
    };
    const prisma = {
      withOrg: vi.fn(async (_org: string, fn: (client: typeof tx) => Promise<unknown>) => fn(tx)),
    };
    const published: Array<{ subject: string; payload: unknown }> = [];
    const bus = {
      publish: vi.fn(async (subject: string, _org: string, payload: unknown) => {
        if (publishImpl) await publishImpl(subject, payload);
        else ScanJob.parse(payload);
        published.push({ subject, payload });
      }),
    };
    const dispatcher = new ScanDispatcherService(
      prisma as never,
      { plan: vi.fn(async () => [asset]) } as unknown as ScanPlannerService,
      bus as never,
    );
    return { dispatcher, tx, published, failedJobs, createdScan };
  }

  it('kicks a legacy tag container asset without throwing (job still dispatched)', async () => {
    const { dispatcher, published } = harness(legacyAsset);
    await expect(
      dispatcher.createScan(orgId, null, { scannerType: 'container', assetSelector: { assetIds: [assetId] }, options: {} }),
    ).resolves.toMatchObject({ id: scanId, jobsDispatched: 1 });
    expect(published).toHaveLength(1);
    expect(published[0].subject).toBe(SUBJECTS.scanJobDispatched);
    expect(ScanJob.parse(published[0].payload).target).toMatchObject({
      kind: 'container_image',
      externalKey: legacyAsset.externalKey,
    });
  });

  it('kicks a digest GHCR demo asset without throwing', async () => {
    const { dispatcher, published } = harness(digestAsset);
    await expect(
      dispatcher.createScan(orgId, null, { scannerType: 'container', assetSelector: { assetIds: [assetId] }, options: {} }),
    ).resolves.toMatchObject({ jobsDispatched: 1 });
    expect(ScanJob.parse(published[0].payload).target).toMatchObject({
      externalKey: DEMO_CONTAINER_IMAGE.externalKey,
      digest: DEMO_CONTAINER_IMAGE.attributes.digest,
      package: DEMO_CONTAINER_IMAGE.attributes.package,
    });
  });

  it('fail-closes the queued job when dispatch throws instead of 500ing the kick', async () => {
    const { dispatcher, tx, failedJobs } = harness(legacyAsset, async () => {
      throw new Error('JetStream not initialized');
    });
    await expect(
      dispatcher.createScan(orgId, null, { scannerType: 'container', assetSelector: {}, options: {} }),
    ).resolves.toMatchObject({ id: scanId, jobsDispatched: 1 });
    expect(failedJobs).toEqual([
      expect.objectContaining({
        status: 'failed',
        error: 'JetStream not initialized',
      }),
    ]);
    expect(tx.scanJob.update).toHaveBeenCalled();
  });
});

describe('ScanDispatcherService requestedBy mapping', () => {
  const orgId = '11111111-1111-4111-8111-111111111111';
  const assetId = '22222222-2222-4222-8222-222222222222';
  const scanId = '33333333-3333-4333-8333-333333333333';
  const jobId = '44444444-4444-4444-8444-444444444444';
  const dbUserId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

  const asset = {
    id: assetId,
    kind: 'container_image',
    externalKey: DEMO_CONTAINER_IMAGE.externalKey,
    attributes: DEMO_CONTAINER_IMAGE.attributes,
    integrationId: null,
  };

  function harness(opts: { userRow?: { id: string } | null; publishThrow?: boolean } = {}) {
    const createdScan = { id: scanId, status: 'running', jobsTotal: 1, jobsCompleted: 0 };
    const failedJobs: unknown[] = [];
    const tx = {
      scan: {
        create: vi.fn(async ({ data }: { data: { requestedBy: string | null } }) => {
          if (data.requestedBy != null && !/^[0-9a-f-]{36}$/i.test(data.requestedBy)) {
            const err = new Error(
              `Inconsistent column data: Error creating UUID, invalid input: ${data.requestedBy}`,
            ) as Error & { code: string };
            err.code = 'P2023';
            throw err;
          }
          return { id: scanId, ...data };
        }),
        findUnique: vi.fn(async () => createdScan),
        update: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
          Object.assign(createdScan, data);
          if (typeof data.jobsCompleted === 'object') createdScan.jobsCompleted += 1;
          return createdScan;
        }),
      },
      scanJob: {
        createMany: vi.fn(async () => ({ count: 1 })),
        findMany: vi.fn(async () => [
          { id: jobId, scanId, orgId, assetId, scannerType: 'container', attempt: 1 },
        ]),
        update: vi.fn(async ({ data }: { data: object }) => {
          failedJobs.push(data);
          return { id: jobId, scanId, ...data };
        }),
        count: vi.fn(async () => 1),
      },
      integration: { findMany: vi.fn(async () => []) },
    };
    const userFind = vi.fn(async ({ where }: { where: { idpSubject: string } }) => {
      if (opts.userRow === undefined) {
        return where.idpSubject === DEMO_IDP_SUBJECT ? { id: dbUserId } : null;
      }
      return opts.userRow;
    });
    const prisma = {
      withOrg: vi.fn(async (_org: string, fn: (client: typeof tx) => Promise<unknown>) => fn(tx)),
      user: { findUnique: userFind },
    };
    const bus = {
      publish: vi.fn(async () => {
        if (opts.publishThrow) throw new Error('JetStream not initialized');
      }),
    };
    const dispatcher = new ScanDispatcherService(
      prisma as never,
      { plan: vi.fn(async () => [asset]) } as unknown as ScanPlannerService,
      bus as never,
    );
    return { dispatcher, tx, userFind, failedJobs };
  }

  it('maps Keycloak demo IdP sub to users.id so create does not P2023', async () => {
    const { dispatcher, tx, userFind } = harness();
    await expect(
      dispatcher.createScan(orgId, DEMO_IDP_SUBJECT, {
        scannerType: 'container',
        assetSelector: {},
        options: {},
      }),
    ).resolves.toMatchObject({ id: scanId, jobsDispatched: 1 });
    expect(userFind).toHaveBeenCalledWith({
      where: { idpSubject: DEMO_IDP_SUBJECT },
      select: { id: true },
    });
    expect(tx.scan.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ requestedBy: dbUserId }),
    });
  });

  it('passes a UUID principal through without an IdP lookup', async () => {
    const { dispatcher, tx, userFind } = harness();
    await dispatcher.createScan(orgId, dbUserId, {
      scannerType: 'sca',
      assetSelector: {},
      options: {},
    });
    expect(userFind).not.toHaveBeenCalled();
    expect(tx.scan.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ requestedBy: dbUserId }),
    });
  });

  it('keeps scheduled/machine kicks unattributed when principal is null', async () => {
    const { dispatcher, tx, userFind } = harness();
    await dispatcher.createScan(orgId, null, { scannerType: 'container', assetSelector: {}, options: {} });
    expect(userFind).not.toHaveBeenCalled();
    expect(tx.scan.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ requestedBy: null }),
    });
  });

  it('4xxs an unmapped IdP subject instead of 500 or unattributed persist', async () => {
    const { dispatcher, tx } = harness({ userRow: null });
    await expect(
      dispatcher.createScan(orgId, 'idp|unknown', { scannerType: 'container', assetSelector: {}, options: {} }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(tx.scan.create).not.toHaveBeenCalled();
  });

  it('still fail-closes dispatch after a successful IdP-mapped create', async () => {
    const { dispatcher, tx, failedJobs } = harness({ publishThrow: true });
    await expect(
      dispatcher.createScan(orgId, DEMO_IDP_SUBJECT, { scannerType: 'container', assetSelector: {}, options: {} }),
    ).resolves.toMatchObject({ id: scanId, jobsDispatched: 1 });
    expect(tx.scan.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ requestedBy: dbUserId }),
    });
    expect(failedJobs).toEqual([expect.objectContaining({ status: 'failed' })]);
  });
});


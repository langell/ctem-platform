import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { ScanContext } from '@ctem/scanner-sdk';
import { ContainerScanError, ContainerScanner } from './container.scanner';

function ctx(kind: string): ScanContext {
  return {
    job: {
      jobId: randomUUID(),
      scanId: randomUUID(),
      orgId: randomUUID(),
      scannerType: 'container',
      assetId: randomUUID(),
      target: { kind, externalKey: 'image:ghcr.io/acme/app:latest' },
      credentialRef: null,
      options: {},
      attempt: 1,
      deadlineAt: new Date(Date.now() + 60_000),
      traceId: 'test',
    },
    workDir: '/tmp',
    checkDeadline: () => true,
    log: () => undefined,
  };
}

describe('ContainerScanner', () => {
  const scanner = new ContainerScanner();

  it('supports only container_image and kubernetes_workload', () => {
    expect(scanner.supports({ target: { kind: 'container_image' } } as never)).toBe(true);
    expect(scanner.supports({ target: { kind: 'kubernetes_workload' } } as never)).toBe(true);
    expect(scanner.supports({ target: { kind: 'repository' } } as never)).toBe(false);
    expect(scanner.supports({ target: { kind: 'iac_stack' } } as never)).toBe(false);
  });

  it('throws for container_image instead of returning { findings: [] }', async () => {
    await expect(scanner.execute(ctx('container_image'))).rejects.toThrow(ContainerScanError);
    await expect(scanner.execute(ctx('container_image'))).rejects.not.toEqual({ findings: [] });
  });

  it('throws for kubernetes_workload instead of returning { findings: [] }', async () => {
    await expect(scanner.execute(ctx('kubernetes_workload'))).rejects.toThrow(ContainerScanError);
  });
});

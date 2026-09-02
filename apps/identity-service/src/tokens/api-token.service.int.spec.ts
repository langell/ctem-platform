import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { UnauthorizedException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { PrismaService, type PrismaClient } from '@ctem/db';
import { createOrg, deleteOrgCascade, ownerClient } from '@ctem/testing';
import { ApiTokenService } from './api-token.service';

/**
 * Full PAT lifecycle against the real database *as the RLS-constrained app
 * role* — the exact conditions the identity service runs under in deployment.
 */
describe('ApiTokenService (integration)', () => {
  let owner: PrismaClient;
  let prisma: PrismaService;
  let service: ApiTokenService;
  let orgId: string;

  beforeAll(async () => {
    owner = ownerClient();
    orgId = (await createOrg(owner)).id;
    prisma = new PrismaService();
    service = new ApiTokenService(prisma);
  });

  afterAll(async () => {
    await deleteOrgCascade(owner, orgId);
    await Promise.all([owner.$disconnect(), prisma.$disconnect()]);
  });

  it('issues a token and stores only its hash', async () => {
    const issued = await service.issue(orgId, 'ci-bot', ['scan:run', 'finding:read']);
    expect(issued.token).toMatch(/^ctem_pat_/);

    const row = await owner.apiToken.findUnique({ where: { id: issued.id } });
    expect(row).not.toBeNull();
    expect(row!.tokenHash).not.toContain(issued.token);
    expect(row!.tokenHash).toBe(createHash('sha256').update(issued.token).digest('hex'));
  });

  it('verifies a valid token and returns its org and scopes', async () => {
    const issued = await service.issue(orgId, 'verifier', ['scan:run']);
    const verified = await service.verify(issued.token);
    expect(verified).toMatchObject({ orgId, name: 'verifier', scopes: ['scan:run'] });
  });

  it('rejects a malformed token', async () => {
    await expect(service.verify('not-a-pat')).rejects.toThrow(UnauthorizedException);
    await expect(service.verify('')).rejects.toThrow(UnauthorizedException);
    await expect(service.verify(undefined as unknown as string)).rejects.toThrow(UnauthorizedException);
  });

  it('rejects an unknown token', async () => {
    await expect(service.verify('ctem_pat_definitely-not-issued')).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('rejects a revoked token', async () => {
    const issued = await service.issue(orgId, 'to-revoke', ['scan:run']);
    await service.revoke(orgId, issued.id);
    await expect(service.verify(issued.token)).rejects.toThrow(UnauthorizedException);
  });

  it('rejects an expired token', async () => {
    const issued = await service.issue(orgId, 'expired', ['scan:run'], new Date(Date.now() - 1000));
    await expect(service.verify(issued.token)).rejects.toThrow(UnauthorizedException);
  });
});

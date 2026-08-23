import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PrismaClient } from '@ctem/db';
import {
  appClient,
  createAsset,
  createFinding,
  createOrg,
  ownerClient,
  withOrg,
} from '@ctem/testing';

/**
 * Proves the row-level security layer actually isolates tenants. Fixtures are
 * arranged with the owner (RLS-bypassing) connection; every assertion runs as
 * `ctem_app`, the role the services connect with in real deployments.
 */
describe('row-level security', () => {
  let owner: PrismaClient;
  let app: PrismaClient;
  let orgA: { id: string };
  let orgB: { id: string };
  let assetA: { id: string };
  let assetB: { id: string };

  beforeAll(async () => {
    owner = ownerClient();
    app = appClient();
    orgA = await createOrg(owner);
    orgB = await createOrg(owner);
    assetA = await createAsset(owner, orgA.id, { name: 'asset-of-org-a' });
    assetB = await createAsset(owner, orgB.id, { name: 'asset-of-org-b' });
    await createFinding(owner, orgA.id, assetA.id, { title: 'finding-of-org-a' });
    await createFinding(owner, orgB.id, assetB.id, { title: 'finding-of-org-b' });
  });

  afterAll(async () => {
    await owner.organization.deleteMany({ where: { id: { in: [orgA.id, orgB.id] } } });
    await Promise.all([owner.$disconnect(), app.$disconnect()]);
  });

  it('covers every tenant table: any table with an orgId column must have RLS enabled and forced', async () => {
    const unprotected = await owner.$queryRaw<{ relname: string }[]>`
      SELECT c.relname
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public'
        AND c.relkind = 'r'
        AND EXISTS (
          SELECT 1 FROM pg_attribute a
          WHERE a.attrelid = c.oid AND a.attname = 'orgId' AND NOT a.attisdropped
        )
        AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
    `;
    // A failure here means a migration added a tenant table without extending
    // libs/db/prisma/manual/000_rls.sql. Fix the SQL, not this test.
    expect(unprotected).toEqual([]);
  });

  it('covers every tenant table: each must carry the tenant_isolation policy', async () => {
    const missing = await owner.$queryRaw<{ relname: string }[]>`
      SELECT c.relname
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public'
        AND c.relkind = 'r'
        AND c.relrowsecurity
        AND NOT EXISTS (
          SELECT 1 FROM pg_policies p
          WHERE p.schemaname = 'public' AND p.tablename = c.relname
            AND p.policyname = 'tenant_isolation'
        )
    `;
    expect(missing).toEqual([]);
  });

  it('fails closed: without an org context the app role sees nothing', async () => {
    expect(await app.asset.count()).toBe(0);
    expect(await app.finding.count()).toBe(0);
    expect(await app.organization.count()).toBe(0);
    // Sanity check that the data is actually there for the owner.
    expect(await owner.asset.count({ where: { orgId: orgA.id } })).toBe(1);
  });

  it('scopes reads to the org in context', async () => {
    const assets = await withOrg(app, orgA.id, (tx) => tx.asset.findMany());
    expect(assets.map((a) => a.id)).toEqual([assetA.id]);

    const findings = await withOrg(app, orgA.id, (tx) => tx.finding.findMany());
    expect(findings.every((f) => f.orgId === orgA.id)).toBe(true);
    expect(findings.some((f) => f.title === 'finding-of-org-b')).toBe(false);
  });

  it('scopes the organizations table to the member org itself', async () => {
    const orgs = await withOrg(app, orgA.id, (tx) => tx.organization.findMany());
    expect(orgs.map((o) => o.id)).toEqual([orgA.id]);
  });

  it('rejects writes stamped with another tenant (WITH CHECK)', async () => {
    await expect(
      withOrg(app, orgA.id, (tx) =>
        tx.asset.create({
          data: {
            orgId: orgB.id, // lies about the tenant
            kind: 'repository',
            externalKey: 'github:evil/cross-tenant',
            name: 'cross-tenant',
            source: 'github',
            exposure: 'internal',
            criticality: 'tier2',
          },
        }),
      ),
    ).rejects.toThrow(/row-level security|denied/i);
  });

  it('makes cross-tenant updates and deletes no-ops', async () => {
    const updated = await withOrg(app, orgA.id, (tx) =>
      tx.finding.updateMany({ where: { orgId: orgB.id }, data: { severity: 'info' } }),
    );
    expect(updated.count).toBe(0);

    const deleted = await withOrg(app, orgA.id, (tx) =>
      tx.asset.deleteMany({ where: { orgId: orgB.id } }),
    );
    expect(deleted.count).toBe(0);
    expect(await owner.asset.count({ where: { id: assetB.id } })).toBe(1);
  });

  it('keeps shared vulnerability intelligence read-only for the app role', async () => {
    await expect(
      app.vulnerability.create({
        data: { id: 'TEST-0001', source: 'test', summary: 'should be rejected', severity: 'low' },
      }),
    ).rejects.toThrow(/permission denied/i);
  });
});

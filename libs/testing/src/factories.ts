import { randomUUID } from 'node:crypto';
import { PrismaClient } from '@ctem/db';

/**
 * Shared fixture builders. `db:seed` and the test suites both build entities
 * through these, so demo data and test data cannot drift apart.
 *
 * Builders take the owner (RLS-bypassing) client: fixtures are arranged from
 * "outside" the tenancy model, then behavior is asserted through the app role.
 */

export function uniqueSlug(prefix: string): string {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

export async function createOrg(
  db: PrismaClient,
  overrides: { name?: string; slug?: string; plan?: string } = {},
) {
  const slug = overrides.slug ?? uniqueSlug('test-org');
  return db.organization.create({
    data: { name: overrides.name ?? slug, slug, plan: overrides.plan ?? 'team' },
  });
}

export async function createUserWithMembership(
  db: PrismaClient,
  orgId: string,
  role = 'developer',
  overrides: { email?: string; name?: string; idpSubject?: string } = {},
) {
  const email = overrides.email ?? `${uniqueSlug('user')}@test.local`;
  const user = await db.user.create({
    data: {
      email,
      name: overrides.name ?? email.split('@')[0],
      idpSubject: overrides.idpSubject ?? `test|${email}`,
    },
  });
  await db.membership.create({ data: { orgId, userId: user.id, role } });
  return user;
}

export async function createAsset(
  db: PrismaClient,
  orgId: string,
  overrides: Record<string, unknown> = {},
) {
  const key = uniqueSlug('github:test/repo');
  return db.asset.create({
    data: {
      orgId,
      kind: 'repository',
      externalKey: key,
      name: key,
      source: 'github',
      exposure: 'internal',
      criticality: 'tier2',
      ...overrides,
    },
  });
}

export async function createFinding(
  db: PrismaClient,
  orgId: string,
  assetId: string,
  overrides: Record<string, unknown> = {},
) {
  return db.finding.create({
    data: {
      orgId,
      assetId,
      fingerprint: uniqueSlug('fp'),
      scannerType: 'sca',
      scannerName: 'ctem-sca',
      title: 'Test finding',
      description: 'Created by @ctem/testing factories.',
      severity: 'medium',
      riskScore: 50,
      location: {},
      ...overrides,
    },
  });
}

/**
 * Deletes an organization and, via ON DELETE CASCADE, every tenant-scoped row
 * under it. Users are global rows and are only removed when `userIds` is given.
 */
export async function deleteOrgCascade(
  db: PrismaClient,
  orgId: string,
  userIds: string[] = [],
): Promise<void> {
  await db.organization.deleteMany({ where: { id: orgId } });
  if (userIds.length) await db.user.deleteMany({ where: { id: { in: userIds } } });
}

/**
 * The demo organization: assets across every kind, a completed scan, findings
 * at several severities, and the asset edges the risk service walks. This is
 * what `make db-seed` installs.
 */
export async function seedDemoOrg(prisma: PrismaClient) {
  const org = await prisma.organization.upsert({
    where: { slug: 'demo' },
    update: {},
    create: { name: 'Demo Corp', slug: 'demo', plan: 'enterprise' },
  });

  const user = await prisma.user.upsert({
    where: { email: 'security@demo.test' },
    update: {},
    create: { email: 'security@demo.test', name: 'Demo Analyst', idpSubject: 'demo|analyst' },
  });

  await prisma.membership.upsert({
    where: { orgId_userId: { orgId: org.id, userId: user.id } },
    update: {},
    create: { orgId: org.id, userId: user.id, role: 'owner' },
  });

  const assets = await Promise.all(
    [
      {
        kind: 'repository',
        externalKey: 'github:demo/payments-api',
        name: 'payments-api',
        source: 'github',
        exposure: 'internet_facing',
        criticality: 'tier0',
        dataClasses: ['pci', 'pii'],
        ownerTeam: 'payments',
      },
      {
        kind: 'container_image',
        externalKey: 'image:ghcr.io/demo/payments-api:latest',
        name: 'payments-api:latest',
        source: 'ecr',
        exposure: 'internet_facing',
        criticality: 'tier0',
      },
      {
        kind: 'repository',
        externalKey: 'github:demo/batch-reconciler',
        name: 'batch-reconciler',
        source: 'github',
        exposure: 'isolated',
        criticality: 'tier3',
        ownerTeam: 'finance-eng',
      },
      {
        kind: 'domain',
        externalKey: 'domain:api.demo.test',
        name: 'api.demo.test',
        source: 'dns_enum',
        exposure: 'internet_facing',
        criticality: 'tier1',
      },
    ].map((data) =>
      prisma.asset.upsert({
        where: { orgId_externalKey: { orgId: org.id, externalKey: data.externalKey } },
        update: {},
        create: { orgId: org.id, ...data },
      }),
    ),
  );

  // The image is built from the repo and deployed behind the public domain —
  // this is the edge set the risk service walks to judge reachability.
  await prisma.assetEdge.createMany({
    skipDuplicates: true,
    data: [
      { orgId: org.id, fromAssetId: assets[1].id, toAssetId: assets[0].id, kind: 'built_from' },
      { orgId: org.id, fromAssetId: assets[3].id, toAssetId: assets[1].id, kind: 'exposes' },
    ],
  });

  const scan = await prisma.scan.create({
    data: {
      orgId: org.id,
      scannerType: 'sca',
      trigger: 'manual',
      status: 'succeeded',
      jobsTotal: 1,
      jobsCompleted: 1,
      startedAt: new Date(Date.now() - 60_000),
      finishedAt: new Date(),
    },
  });

  await prisma.finding.createMany({
    skipDuplicates: true,
    data: [
      {
        orgId: org.id,
        assetId: assets[0].id,
        fingerprint: 'seed-critical-internet',
        scannerType: 'sca',
        scannerName: 'ctem-sca',
        title: 'CVE-2024-0001 in express@4.17.1',
        description: 'Prototype pollution leading to remote code execution.',
        severity: 'critical',
        riskScore: 94,
        cvssScore: 9.8,
        epssScore: 0.87,
        kev: true,
        fixAvailable: true,
        fixedVersion: '4.19.2',
        location: { packageName: 'express', packageVersion: '4.17.1', packageEcosystem: 'npm' },
        evidence: { reachability: 'reachable', dependencyPath: ['express'] },
        slaDueAt: new Date(Date.now() + 24 * 3_600_000),
      },
      {
        // Same CVSS, isolated tier-3 asset — the score is what makes the point.
        orgId: org.id,
        assetId: assets[2].id,
        fingerprint: 'seed-critical-isolated',
        scannerType: 'sca',
        scannerName: 'ctem-sca',
        title: 'CVE-2024-0001 in express@4.17.1',
        description: 'Prototype pollution leading to remote code execution.',
        severity: 'critical',
        riskScore: 41,
        cvssScore: 9.8,
        epssScore: 0.87,
        kev: true,
        validation: 'not_reachable',
        fixAvailable: true,
        fixedVersion: '4.19.2',
        location: { packageName: 'express', packageVersion: '4.17.1', packageEcosystem: 'npm' },
        evidence: { reachability: 'not_reachable', dependencyPath: ['express'] },
      },
      {
        orgId: org.id,
        assetId: assets[3].id,
        fingerprint: 'seed-asm-takeover',
        scannerType: 'asm',
        scannerName: 'ctem-asm',
        title: 'Possible subdomain takeover on api.demo.test',
        description: 'Dangling CNAME to an unclaimed provider hostname.',
        severity: 'high',
        riskScore: 78,
        location: { url: 'api.demo.test' },
      },
    ],
  });

  await prisma.scanJob.create({
    data: {
      orgId: org.id,
      scanId: scan.id,
      assetId: assets[0].id,
      scannerType: 'sca',
      status: 'succeeded',
      findingCount: 2,
      startedAt: new Date(Date.now() - 60_000),
      finishedAt: new Date(),
    },
  });

  return { org, user, assets, scan };
}

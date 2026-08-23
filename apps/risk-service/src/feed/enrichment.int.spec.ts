import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { EventBus } from '@ctem/events';
import type { PrismaClient } from '@ctem/db';
import { createAsset, createFinding, createOrg, ownerClient } from '@ctem/testing';
import { FeedStore } from './feed.store';
import { EnrichmentService } from './enrichment.service';

/**
 * Full enrichment pass against the real database: mirrored advisory picks up
 * KEV + EPSS (stubbed feeds), the change lands on the org's open finding, and
 * a rescore event goes out for exactly that org and finding.
 */
describe('EnrichmentService (integration)', () => {
  const cve = `CVE-2099-${Math.floor(Math.random() * 90000) + 10000}`;
  const vulnId = `TEST-ENRICH-${cve}`;
  let owner: PrismaClient;
  let store: FeedStore;
  let service: EnrichmentService;
  let orgId: string;
  let findingId: string;
  const published: Array<{ subject: string; orgId: string; payload: unknown }> = [];

  beforeAll(async () => {
    owner = ownerClient();
    store = new FeedStore();
    const busStub = {
      publish: vi.fn(async (subject: string, orgId: string, payload: unknown) => {
        published.push({ subject, orgId, payload });
      }),
    } as unknown as EventBus;
    service = new EnrichmentService(store, busStub);

    orgId = (await createOrg(owner)).id;
    const asset = await createAsset(owner, orgId);
    findingId = (
      await createFinding(owner, orgId, asset.id, {
        title: `enrichment target ${cve}`,
        identifiers: [{ system: 'GHSA', value: vulnId }, { system: 'alias', value: cve }],
        epssScore: null,
        kev: false,
      })
    ).id;

    await owner.vulnerability.create({
      data: { id: vulnId, source: 'GHSA', aliases: [cve], summary: 'enrichment test' },
    });

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const href = String(url);
        if (href.includes('epss')) {
          return new Response(
            JSON.stringify({ data: [{ cve, epss: '0.9110', percentile: '0.9990' }] }),
            { status: 200 },
          );
        }
        // KEV catalog
        return new Response(
          JSON.stringify({ vulnerabilities: [{ cveID: cve, dueDate: '2099-01-15' }] }),
          { status: 200 },
        );
      }),
    );
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    await owner.vulnerability.deleteMany({ where: { id: vulnId } });
    await owner.organization.deleteMany({ where: { id: orgId } });
    await Promise.all([owner.$disconnect(), store.$disconnect()]);
  });

  it('enriches the advisory, propagates to the finding, and requests a rescore', async () => {
    const summary = await service.refresh();
    expect(summary.kevChanged).toBeGreaterThanOrEqual(1);
    expect(summary.epssChanged).toBeGreaterThanOrEqual(1);
    expect(summary.findingsUpdated).toBeGreaterThanOrEqual(1);

    const vuln = await owner.vulnerability.findUnique({ where: { id: vulnId } });
    expect(vuln).toMatchObject({ kev: true, epssScore: 0.911, epssPercentile: 0.999 });
    expect(vuln!.kevDueDate?.toISOString().slice(0, 10)).toBe('2099-01-15');

    const finding = await owner.finding.findUnique({ where: { id: findingId } });
    expect(finding).toMatchObject({ kev: true, epssScore: 0.911 });

    const rescore = published.find(
      (e) => e.subject === 'ctem.risk.rescore_requested' && e.orgId === orgId,
    );
    expect(rescore).toBeDefined();
    expect((rescore!.payload as { findingIds: string[] }).findingIds).toContain(findingId);
  });

  it('is quiet on a second pass with unchanged intel', async () => {
    published.length = 0;
    const summary = await service.refresh();
    // Our advisory is already correct; no rescore should target our org again.
    expect(published.find((e) => e.orgId === orgId)).toBeUndefined();
    expect(summary.findingsUpdated).toBe(0);
  });
});

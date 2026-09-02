/**
 * End-to-end smoke test for the golden path, run against a live stack:
 *
 *   make infra && make db-migrate && make dev     # in one terminal
 *   make e2e                                      # in another
 *
 * It provisions two throwaway orgs with machine tokens, then walks the real
 * surface: gateway auth (PAT), proxying, asset registration, tenant isolation
 * across orgs, scan dispatch and the findings/negative paths. Cleans up after
 * itself and exits non-zero if any step fails.
 */
/* eslint-disable no-console -- console output is this script's user interface */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ROLE_PERMISSIONS } from '../../libs/contracts/src/index';
import { encodePrincipal } from '../../libs/auth/src/principal';
import {
  createOrg,
  deleteOrgCascade,
  ownerClient,
  uniqueSlug,
} from '../../libs/testing/src/index';

// ---------------------------------------------------------------- bootstrap

// Load .env the same way the services see it, without overriding the shell.
try {
  for (const line of readFileSync(resolve(__dirname, '../../.env'), 'utf8').split('\n')) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
} catch {
  /* no .env — defaults below match .env.example */
}

const GATEWAY = process.env.SMOKE_GATEWAY_URL ?? 'http://localhost:3000';
const IDENTITY = process.env.IDENTITY_SERVICE_URL ?? 'http://localhost:3001';

let failures = 0;
async function step(name: string, fn: () => Promise<string | void>): Promise<void> {
  try {
    const detail = await fn();
    console.log(`  ✓ ${name}${detail ? ` — ${detail}` : ''}`);
  } catch (err) {
    failures += 1;
    console.error(`  ✗ ${name}\n      ${(err as Error).message}`);
  }
}

function expect(cond: boolean, message: string): void {
  if (!cond) throw new Error(message);
}

/** The smoke runner acts as the service mesh when talking to internal APIs. */
function principalHeaders(orgId: string): Record<string, string> {
  const encoded = encodePrincipal({
    userId: 'smoke-runner',
    orgId,
    role: 'owner',
    permissions: ROLE_PERMISSIONS.owner,
    serviceAccount: 'smoke-runner',
    traceId: 'smoke',
  });
  return {
    'x-ctem-principal': encoded.value,
    'x-ctem-principal-signature': encoded.signature,
    'content-type': 'application/json',
  };
}

async function api(
  base: string,
  method: string,
  path: string,
  opts: {
    token?: string;
    headers?: Record<string, string>;
    body?: unknown;
    timeoutMs?: number;
  } = {},
): Promise<{ status: number; json: Record<string, unknown> | null }> {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.body ? { 'content-type': 'application/json' } : {}),
      ...opts.headers,
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, json };
}

// ------------------------------------------------------------------- steps

async function main(): Promise<void> {
  console.log(`smoke: gateway=${GATEWAY} identity=${IDENTITY}\n`);

  const db = ownerClient();
  const orgA = await createOrg(db, { slug: uniqueSlug('smoke-a') });
  const orgB = await createOrg(db, { slug: uniqueSlug('smoke-b') });
  let patA = '';
  let patB = '';
  let orgAAssetId = '';
  let orgAScanId = '';
  const assetName = uniqueSlug('smoke-asset');

  try {
    const alive = async (base: string) => {
      const res = await fetch(`${base}/health/live`, { signal: AbortSignal.timeout(3000) }).catch(
        () => null,
      );
      expect(res !== null && res.ok, `${base} is not responding — is \`make dev\` running?`);
    };
    await step('gateway is up', () => alive(GATEWAY));
    await step('identity-service is up', () => alive(IDENTITY));

    if (failures) return; // nothing else can work

    await step('issue machine tokens (identity API, signed principal)', async () => {
      const a = await api(IDENTITY, 'POST', '/internal/tokens', {
        headers: principalHeaders(orgA.id),
        body: {
          name: 'smoke-a',
          scopes: [
            'asset:read',
            'asset:write',
            'scan:read',
            'scan:run',
            'finding:read',
            'policy:read',
            'policy:write',
            'integration:manage',
          ],
        },
      });
      expect(a.status < 300 && a.json?.token, `org A token: HTTP ${a.status}`);
      patA = a.json.token;

      const b = await api(IDENTITY, 'POST', '/internal/tokens', {
        headers: principalHeaders(orgB.id),
        body: {
          name: 'smoke-b',
          scopes: ['asset:read', 'scan:read', 'finding:read', 'policy:read', 'policy:write'],
        },
      });
      expect(b.status < 300 && b.json?.token, `org B token: HTTP ${b.status}`);
      patB = b.json.token;
    });

    await step('gateway rejects a missing token', async () => {
      const res = await api(GATEWAY, 'GET', '/v1/assets');
      expect(res.status === 401, `expected 401, got ${res.status}`);
    });

    await step('gateway rejects a bogus PAT', async () => {
      const res = await api(GATEWAY, 'GET', '/v1/assets', { token: 'ctem_pat_bogus' });
      expect(res.status === 401, `expected 401, got ${res.status}`);
    });

    await step('register an asset through the gateway (PAT auth, proxy, RLS write)', async () => {
      const res = await api(GATEWAY, 'POST', '/v1/assets', {
        token: patA,
        body: {
          kind: 'repository',
          externalKey: `github:smoke/${assetName}`,
          name: assetName,
          source: 'github',
          exposure: 'internet_facing',
          criticality: 'tier1',
        },
      });
      expect(res.status < 300, `expected 2xx, got ${res.status}: ${JSON.stringify(res.json)}`);
    });

    await step('org A sees its asset', async () => {
      const res = await api(GATEWAY, 'GET', '/v1/assets', { token: patA });
      expect(res.status === 200, `expected 200, got ${res.status}`);
      const items = (res.json?.items ?? res.json ?? []) as Array<{ id: string; name: string }>;
      const created = items.find((a) => a.name === assetName);
      expect(Boolean(created?.id), 'created asset missing from org A listing');
      orgAAssetId = created!.id;
    });

    await step('org B cannot read org A asset detail or graph', async () => {
      expect(Boolean(orgAAssetId), 'missing org A asset id from the previous step');
      const detail = await api(GATEWAY, 'GET', `/v1/assets/${orgAAssetId}`, { token: patB });
      expect(detail.status === 404, `expected 404 on asset detail, got ${detail.status}`);
      const graph = await api(GATEWAY, 'GET', `/v1/assets/${orgAAssetId}/graph`, { token: patB });
      expect(graph.status === 404, `expected 404 on asset graph, got ${graph.status}`);
    });

    await step('org B cannot see org A data (tenant isolation, full stack)', async () => {
      const res = await api(GATEWAY, 'GET', '/v1/assets', { token: patB });
      expect(res.status === 200, `expected 200, got ${res.status}`);
      const items = res.json?.items ?? res.json ?? [];
      expect(
        !items.some((a: { name: string }) => a.name === assetName),
        `org A's asset leaked into org B's listing`,
      );
    });

    await step('a PAT without the permission is denied (403)', async () => {
      const res = await api(GATEWAY, 'POST', '/v1/assets', {
        token: patB,
        body: {
          kind: 'repository',
          externalKey: 'github:smoke/denied',
          name: 'denied',
          source: 'github',
        },
      });
      expect(res.status === 403, `expected 403, got ${res.status}`);
    });

    const awaitScan = async (id: string): Promise<Record<string, unknown>> => {
      let scan: Record<string, unknown> = {};
      for (let i = 0; i < 30; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        const read = await api(GATEWAY, 'GET', `/v1/scans/${id}`, { token: patA });
        expect(read.status === 200, `GET /v1/scans/${id} returned ${read.status}`);
        scan = read.json ?? {};
        if (['succeeded', 'failed', 'partial'].includes(String(scan.status))) break;
      }
      return scan;
    };

    await step('dispatch a source SCA scan that fails closed without a cloneable repo', async () => {
      const created = await api(GATEWAY, 'POST', '/v1/scans', {
        token: patA,
        body: { scannerType: 'sca', assetSelector: {}, options: {} },
      });
      expect(
        created.status < 300 && Boolean(created.json?.id),
        `expected 2xx with id, got ${created.status}: ${JSON.stringify(created.json)}`,
      );
      orgAScanId = String(created.json!.id);
      const scan = await awaitScan(orgAScanId);
      // github:smoke/… is not a real repo. Source SCA must throw rather than
      // succeed with zero findings (that would auto-resolve prior hits).
      expect(
        scan.status === 'failed',
        `scan ended as '${scan.status}' — expected failed (source SCA fails closed when checkout cannot run)`,
      );
      return `scan ${orgAScanId} failed closed`;
    });

    await step('org B cannot read org A scan (GET-by-id is 404, not 500)', async () => {
      expect(Boolean(orgAScanId), 'missing org A scan id from the previous step');
      const res = await api(GATEWAY, 'GET', `/v1/scans/${orgAScanId}`, { token: patB });
      expect(res.status === 404, `expected 404 on scan, got ${res.status}`);
      const spoofed = await api(GATEWAY, 'GET', `/v1/scans/${orgAScanId}?orgId=${orgA.id}`, {
        token: patB,
        headers: { 'x-ctem-org': orgA.id },
      });
      expect(spoofed.status === 404, `expected 404 when spoofing org, got ${spoofed.status}`);
    });

    await step('SBOM ingest produces real findings (queries OSV — needs internet)', async () => {
      const created = await api(GATEWAY, 'POST', '/v1/scans/sbom', {
        token: patA,
        body: {
          assetExternalKey: `github:smoke/${assetName}`,
          format: 'cyclonedx-json',
          document: {
            bomFormat: 'CycloneDX',
            specVersion: '1.5',
            metadata: { component: { 'bom-ref': 'root', name: assetName, version: '1.0.0' } },
            components: [
              {
                'bom-ref': 'pkg:npm/express@4.17.1',
                purl: 'pkg:npm/express@4.17.1',
                name: 'express',
                version: '4.17.1',
              },
              {
                'bom-ref': 'pkg:npm/qs@6.7.0',
                purl: 'pkg:npm/qs@6.7.0',
                name: 'qs',
                version: '6.7.0',
              },
            ],
            dependencies: [
              { ref: 'root', dependsOn: ['pkg:npm/express@4.17.1'] },
              { ref: 'pkg:npm/express@4.17.1', dependsOn: ['pkg:npm/qs@6.7.0'] },
            ],
          },
        },
      });
      expect(
        created.status < 300 && Boolean(created.json?.id),
        `expected 2xx with id, got ${created.status}: ${JSON.stringify(created.json)}`,
      );

      const scan = await awaitScan(String(created.json!.id));
      expect(scan.status === 'succeeded', `SBOM scan ended as '${scan.status}'`);
      const jobs = (scan.jobs ?? []) as Array<{ findingCount: number }>;
      const found = jobs.reduce((n, j) => n + (j.findingCount ?? 0), 0);
      expect(
        found > 0,
        'SBOM scan succeeded but found nothing for express@4.17.1 — OSV unreachable?',
      );
      return `${found} findings for express@4.17.1`;
    });

    await step('scanner misses are mirrored by the feed ingester', async () => {
      let sync: { advisories: number } | null = null;
      for (let i = 0; i < 15 && !sync; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        sync = await db.vulnPackageSync.findUnique({
          where: { ecosystem_packageName: { ecosystem: 'npm', packageName: 'express' } },
        });
      }
      expect(
        sync !== null,
        'no vuln_package_sync row for npm/express — observed event never reached the feed ingester',
      );
      return `mirror holds ${sync!.advisories} advisories for npm/express`;
    });

    await step('GitHub discovery inventories the fixture repo (live GitHub)', async () => {
      // ctem-scan-target is public, so this works tokenless via the public
      // listing. With GITHUB_TOKEN set (asset-service reads it from ITS env,
      // e.g. `export GITHUB_TOKEN=$(gh auth token)` before `make dev`), the
      // authenticated private-repo path is exercised instead.
      await db.integration.create({
        data: {
          orgId: orgA.id,
          provider: 'github',
          displayName: 'smoke-github',
          config: { owner: 'langell', ownerType: 'user', repos: ['ctem-scan-target'] },
          credentialRef: 'env:GITHUB_TOKEN',
        },
      });

      const res = await api(GATEWAY, 'POST', '/v1/assets/discover', {
        token: patA,
        // Live GitHub listing regularly exceeds the default 10s client budget.
        timeoutMs: 30_000,
      });
      expect(res.status < 300, `discover returned ${res.status}: ${JSON.stringify(res.json)}`);
      const results = res.json as unknown as Array<{ upserted: number; error: string | null }>;
      expect(
        results.some((r) => r.upserted >= 1 && r.error === null),
        `discovery found nothing: ${JSON.stringify(results)}`,
      );

      const assets = await api(GATEWAY, 'GET', '/v1/assets', { token: patA });
      const items = (assets.json?.items ?? []) as Array<{ externalKey: string; source: string }>;
      expect(
        items.some((a) => a.externalKey === 'github:langell/ctem-scan-target'),
        'ctem-scan-target missing from the inventory after discovery',
      );
      return `github:langell/ctem-scan-target inventoried from live GitHub (${process.env.GITHUB_TOKEN ? 'authenticated' : 'public listing'})`;
    });

    await step('org B cannot see org A GitHub-discovered assets', async () => {
      const res = await api(GATEWAY, 'GET', '/v1/assets', { token: patB });
      expect(res.status === 200, `expected 200, got ${res.status}`);
      const items = (res.json?.items ?? res.json ?? []) as Array<{ externalKey: string }>;
      expect(
        !items.some((a) => a.externalKey === 'github:langell/ctem-scan-target'),
        `org A's GitHub-discovered asset leaked into org B's listing`,
      );
    });

    await step('threat-intel refresh enriches findings (KEV/EPSS — needs internet)', async () => {
      const RISK = process.env.RISK_SERVICE_URL ?? 'http://localhost:3005';
      const res = await api(RISK, 'POST', '/internal/risk/feed/refresh', {
        headers: principalHeaders(orgA.id),
      });
      expect(res.status < 300, `refresh returned ${res.status}: ${JSON.stringify(res.json)}`);

      const findings = await api(GATEWAY, 'GET', '/v1/findings', { token: patA });
      const items = (findings.json?.items ?? findings.json ?? []) as Array<{
        scannerType: string;
        epssScore: number | null;
      }>;
      expect(
        items.some((f) => f.scannerType === 'sca' && f.epssScore !== null),
        'no SCA finding carries an EPSS score after the refresh',
      );
      return `advisories=${res.json!.advisories} epssChanged=${res.json!.epssChanged} findingsUpdated=${res.json!.findingsUpdated}`;
    });

    await step('findings are queryable and explain their dependency path', async () => {
      const res = await api(GATEWAY, 'GET', '/v1/findings', { token: patA });
      expect(res.status === 200, `expected 200, got ${res.status}`);
      const items = (res.json?.items ?? res.json ?? []) as Array<{
        scannerType: string;
        location: { packageName?: string };
        evidence: { dependencyPath?: string[] };
      }>;
      expect(
        items.some((f) => f.scannerType === 'sca'),
        'no SCA findings in the org listing after the SBOM scan',
      );

      const transitive = items.find((f) => f.location?.packageName === 'qs');
      expect(transitive !== undefined, 'expected a finding for the transitive qs@6.7.0');
      expect(
        JSON.stringify(transitive!.evidence?.dependencyPath) === JSON.stringify(['express', 'qs']),
        `qs finding should explain its path as express → qs, got ${JSON.stringify(transitive!.evidence?.dependencyPath)}`,
      );
      return 'transitive qs finding carries path express → qs';
    });

    let orgAFindingId = '';
    await step('org B cannot list org A findings (tenant isolation)', async () => {
      const listed = await api(GATEWAY, 'GET', '/v1/findings', { token: patA });
      const aItems = (listed.json?.items ?? []) as Array<{ id: string; title: string }>;
      expect(aItems.length > 0, 'org A should have findings after the SBOM scan');
      orgAFindingId = aItems[0]!.id;

      const res = await api(GATEWAY, 'GET', '/v1/findings', { token: patB });
      expect(res.status === 200, `expected 200, got ${res.status}`);
      const items = (res.json?.items ?? []) as Array<{ id: string }>;
      expect(
        !items.some((f) => f.id === orgAFindingId),
        `org A's finding ${orgAFindingId} leaked into org B's listing`,
      );
    });

    await step('org B cannot read org A finding detail or risk', async () => {
      expect(Boolean(orgAFindingId), 'missing org A finding id from the previous step');
      const detail = await api(GATEWAY, 'GET', `/v1/findings/${orgAFindingId}`, { token: patB });
      expect(detail.status === 404, `expected 404 on detail, got ${detail.status}`);
      const risk = await api(GATEWAY, 'GET', `/v1/findings/${orgAFindingId}/risk`, { token: patB });
      expect(risk.status === 404, `expected 404 on risk, got ${risk.status}`);
    });

    await step('client-supplied org header cannot switch tenant on findings', async () => {
      const res = await api(GATEWAY, 'GET', `/v1/findings?orgId=${orgA.id}`, {
        token: patB,
        headers: { 'x-ctem-org': orgA.id },
      });
      expect(res.status === 200, `expected 200, got ${res.status}`);
      const items = (res.json?.items ?? []) as Array<{ id: string }>;
      expect(
        !items.some((f) => f.id === orgAFindingId),
        'x-ctem-org / ?orgId= leaked org A findings to an org B token',
      );
    });

    let orgAPolicyId = '';
    await step('create ordered notify policies for org A', async () => {
      const later = await api(GATEWAY, 'POST', '/v1/policies', {
        token: patA,
        body: {
          name: 'smoke-later',
          condition: { kevOnly: true },
          actions: ['notify'],
          priority: 20,
        },
      });
      expect(later.status < 300, `create later: HTTP ${later.status} ${JSON.stringify(later.json)}`);
      const first = await api(GATEWAY, 'POST', '/v1/policies', {
        token: patA,
        body: {
          name: 'smoke-first',
          condition: { severityAtLeast: 'critical' },
          actions: ['notify'],
          priority: 10,
        },
      });
      expect(first.status < 300, `create first: HTTP ${first.status} ${JSON.stringify(first.json)}`);
      orgAPolicyId = first.json.id;

      const listed = await api(GATEWAY, 'GET', '/v1/policies', { token: patA });
      expect(listed.status === 200, `expected 200, got ${listed.status}`);
      const rows = listed.json as Array<{ id: string; name: string; priority: number }>;
      const smoke = rows.filter((p) => p.name.startsWith('smoke-'));
      expect(
        smoke.map((p) => p.name).join(',') === 'smoke-first,smoke-later',
        `expected first-then-later order, got ${smoke.map((p) => `${p.name}:${p.priority}`).join(',')}`,
      );
    });

    await step('update persists a new priority order', async () => {
      expect(Boolean(orgAPolicyId), 'missing org A policy id');
      const patched = await api(GATEWAY, 'PATCH', `/v1/policies/${orgAPolicyId}`, {
        token: patA,
        body: { priority: 40 },
      });
      expect(patched.status < 300, `update: HTTP ${patched.status} ${JSON.stringify(patched.json)}`);
      const listed = await api(GATEWAY, 'GET', '/v1/policies', { token: patA });
      const rows = (listed.json as Array<{ name: string; priority: number }>).filter((p) =>
        p.name.startsWith('smoke-'),
      );
      expect(
        rows.map((p) => p.name).join(',') === 'smoke-later,smoke-first',
        `expected later-then-first after update, got ${rows.map((p) => `${p.name}:${p.priority}`).join(',')}`,
      );
    });

    await step('org B cannot read or update an org A policy (404)', async () => {
      expect(Boolean(orgAPolicyId), 'missing org A policy id');
      const read = await api(GATEWAY, 'GET', `/v1/policies/${orgAPolicyId}`, { token: patB });
      expect(read.status === 404, `expected 404 on get, got ${read.status}`);
      const write = await api(GATEWAY, 'PATCH', `/v1/policies/${orgAPolicyId}`, {
        token: patB,
        body: { name: 'stolen' },
      });
      expect(write.status === 404, `expected 404 on update, got ${write.status}`);
    });

    await step('editor accepts ticket and refuses fail-build plus a tenant webhook URL', async () => {
      const ticket = await api(GATEWAY, 'POST', '/v1/policies', {
        token: patA,
        body: {
          name: 'smoke-ticket',
          condition: { kevOnly: true },
          actions: ['ticket'],
          priority: 99,
        },
      });
      expect(ticket.status < 300, `expected ticket create, got ${ticket.status} ${JSON.stringify(ticket.json)}`);
      expect(ticket.json?.actions?.join(',') === 'ticket', `expected ticket actions, got ${JSON.stringify(ticket.json)}`);

      const failBuild = await api(GATEWAY, 'POST', '/v1/policies', {
        token: patA,
        body: {
          name: 'smoke-fail-build',
          condition: { kevOnly: true },
          actions: ['fail_build'],
          priority: 98,
        },
      });
      expect(failBuild.status === 400, `expected 400 for fail_build, got ${failBuild.status}`);

      const webhook = await api(GATEWAY, 'POST', '/v1/policies', {
        token: patA,
        body: {
          name: 'smoke-webhook',
          condition: { kevOnly: true },
          actions: ['notify'],
          priority: 99,
          webhookUrl: 'https://attacker.test/hooks/tenant',
        },
      });
      expect(webhook.status === 400, `expected 400 for tenant webhook URL, got ${webhook.status}`);

      const jiraUrl = await api(GATEWAY, 'POST', '/v1/policies', {
        token: patA,
        body: {
          name: 'smoke-jira-url',
          condition: { kevOnly: true },
          actions: ['ticket'],
          priority: 99,
          jiraUrl: 'https://evil.example/jira',
        },
      });
      expect(jiraUrl.status === 400, `expected 400 for tenant Jira URL, got ${jiraUrl.status}`);
    });
  } finally {
    await deleteOrgCascade(db, orgA.id).catch(() => undefined);
    await deleteOrgCascade(db, orgB.id).catch(() => undefined);
    await db.$disconnect();
  }
}

main()
  .then(() => {
    console.log(failures ? `\nsmoke: ${failures} step(s) FAILED` : '\nsmoke: all steps passed');
    process.exit(failures ? 1 : 0);
  })
  .catch((err) => {
    console.error('\nsmoke: aborted —', err);
    process.exit(1);
  });

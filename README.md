# CTEM Platform

Continuous Threat Exposure Management. Discovers what you own, scans it continuously across four surfaces, and prioritizes findings by real exposure rather than raw CVSS.

This repository is a **scaffold**: the architecture, contracts, data model, event flows and service boundaries are in place and compile. Scanner internals and connectors are stubbed with explicit `TODO`s marking the extension points.

## Stack

| Concern | Choice |
| --- | --- |
| Language | TypeScript, NestJS 11, Node 22 |
| Repo | Nx monorepo, pnpm workspaces, TS project references |
| Transport | REST between services, NATS JetStream for the event bus |
| Data | Postgres 17 (Prisma), Redis, S3-compatible object store |
| Tenancy | Multi-tenant SaaS, `org_id` everywhere, Postgres row-level security |
| Auth | OIDC/JWT at the gateway, HMAC-signed principal internally, RBAC |

## Quick start

```bash
make setup      # install, start infra, migrate, build
make db-seed    # a demo org with assets and findings
make dev        # run every service with watch mode
```

Gateway on `http://localhost:3000`, OpenAPI at `/docs`.

## Testing

```bash
make test       # unit tier: pure logic, seconds, no infra
make test-int   # integration tier: real Postgres + RLS (needs infra)
make e2e        # smoke the golden path against a running `make dev` stack
```

The tiers, conventions and definition-of-done live in [docs/testing.md](docs/testing.md).
Shared fixtures (factories, a test OIDC issuer, RLS-aware db clients) are in `@ctem/testing`.

## Services

**Control plane**

| Service | Port | Owns |
| --- | --- | --- |
| `api-gateway` | 3000 | Public API, token verification, principal minting, rate limiting |
| `identity-service` | 3001 | Orgs, users, memberships, roles, machine tokens |
| `asset-service` | 3002 | Asset inventory, asset graph, discovery connectors |
| `orchestrator-service` | 3003 | Scan planning, job dispatch, scheduling, scan lifecycle |
| `findings-service` | 3004 | Normalization, dedup, lifecycle, triage, audit trail |
| `risk-service` | 3005 | Risk scoring, policy evaluation, SLAs, exceptions |
| `reporting-service` | 3006 | Dashboards, trends, exports |
| `notification-service` | 3007 | Slack, email, webhooks, ticketing |

**Scanner workers** — no HTTP surface, pure JetStream consumers, horizontally scalable.

| Worker | Scanner types |
| --- | --- |
| `scanner-sca` | `sca` — dependencies, SBOM ingest, advisory matching |
| `scanner-sast` | `sast` — source code rules and taint analysis |
| `scanner-container-iac` | `container`, `iac` — image layers, Terraform/K8s misconfig |
| `scanner-asm` | `asm` — external attack surface, subdomain takeover |

**Shared libraries** — `@ctem/contracts` (zod schemas + event catalog), `@ctem/db` (Prisma + RLS), `@ctem/auth`, `@ctem/events`, `@ctem/storage`, `@ctem/config`, `@ctem/observability`, `@ctem/service-kit`, `@ctem/scanner-sdk`.

## How a scan flows

```
POST /v1/scans
  → orchestrator plans (which assets does this scanner apply to?)
  → persists Scan + ScanJob rows
  → publishes ctem.scan.job.dispatched per asset
      → scanner worker executes, uploads raw output to S3
      → publishes ctem.finding.reported + ctem.scan.job.completed
          → findings-service normalizes, dedups by fingerprint,
            auto-resolves anything no longer reported
          → publishes ctem.finding.created / .updated
              → risk-service scores, then evaluates policy
                  → ctem.policy.violated → notification-service
          → orchestrator closes the scan when all jobs report
```

## What makes this different from an SCA tool

1. **Asset graph, not an asset list.** Findings hang off assets that know their exposure, business criticality, data classification and owner. A recursive walk answers "is this reachable from the internet?"
2. **Explainable risk scores.** Severity × exploitability (EPSS/KEV) × exposure × business criticality, with the factor breakdown returned by `GET /v1/findings/:id/risk`. The seed data ships the same CVE on two assets scoring 94 and 41.
3. **Validation as a first-class state.** `not_validated → reachable → exploitable` moves the score. Prioritizing by CVSS alone is what produces backlogs nobody works.
4. **Attack surface discovery.** Continuously enumerating what you expose, including the assets nobody remembers owning.
5. **Policy with teeth.** Ordered rules that can notify, ticket, fail a build or block a deploy, with SLAs and approved, expiring exceptions.

## Adding a scanner

```ts
@Injectable()
export class MyScanner extends BaseScanner {
  readonly type = 'secrets';
  readonly name = 'ctem-secrets';
  readonly version = '0.1.0';

  async execute(ctx: ScanContext): Promise<ScanOutcome> {
    return { findings: [/* RawFinding[] */] };
  }
}

@Module({ imports: [ScannerModule.register(MyScanner)] })
export class AppModule {}
```

Queue subscription, retries, artifact upload, tenancy and event publication are handled by the SDK.

## Tenancy

Every tenant table carries `orgId` and has RLS enabled with `FORCE`. The app connects as `ctem_app`, a non-superuser, and every query runs inside `PrismaService.withOrg()`, which sets `app.current_org_id` for the transaction. A query that escapes its org returns zero rows rather than another tenant's data. Cross-tenant work must go through `unsafeCrossTenant(reason, fn)`, which logs and is easy to grep for in review.

## Not yet built

Scanner internals beyond the SCA SBOM path (repo cloning and lockfile resolution, image layer walking, IaC parsing, port scanning), discovery connectors, NVD/GHSA feeds and EPSS paging for the vulnerability mirror (OSV advisories are mirrored demand-driven today; unmirrored packages still hit OSV live once), reachability analysis, the web UI, distributed scheduling (the schedulers use naive intervals and need leader election before running multiple replicas), and Redis-backed rate limiting.

See `docs/architecture.md` for the full design and the build order.

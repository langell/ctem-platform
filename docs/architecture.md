# Architecture

## Decisions taken

| Decision        | Choice                                              | Why                                                                                     |
| --------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Language        | TypeScript / NestJS 11                              | One language across API and a future web UI; DI and module boundaries come for free     |
| Topology        | Microservices from day one                          | Scanner workloads and control-plane traffic scale on completely different curves        |
| Repo            | Nx monorepo, pnpm workspaces, TS project references | Shared contracts stay in lockstep with every service; affected-only builds              |
| Sync transport  | REST                                                | Simple to debug, easy for partners to integrate against                                 |
| Async transport | NATS JetStream                                      | Durable, replayable, cheap to run; consumer groups give free horizontal scaling         |
| Primary store   | Postgres 17 + Prisma                                | Relational integrity for the asset/finding graph, JSONB for scanner payloads            |
| Cache/queue     | Redis                                               | Session and rate-limit state, short-lived scanner coordination                          |
| Blobs           | S3-compatible                                       | Raw scanner output and SBOMs do not belong in a relational database                     |
| Tenancy         | Shared database, `org_id` + row-level security      | Matches how this category is sold; isolation is enforced by Postgres, not by discipline |
| Auth            | OIDC/JWT at the edge, signed principal internally   | Keeps the IdP off the hot path; services stay stateless                                 |

## Boundaries

Services are drawn around **rate of change and ownership**, not around database tables.

```
                        ┌──────────────┐
   users, CI ─────────► │ api-gateway  │  JWT/PAT → signed principal
                        └──────┬───────┘
        ┌──────────────┬───────┼────────┬──────────────┬──────────────┐
        ▼              ▼       ▼        ▼              ▼              ▼
   identity        asset   orchestrator findings     risk         reporting
   orgs/users   inventory   scan plan   normalize   score+policy   dashboards
   RBAC/tokens   + graph    + dispatch  dedup/triage  SLA/except.   trends
        └──────────────┴───────┬────────┴──────────────┴──────────────┘
                               │  NATS JetStream
        ┌──────────────┬───────┴────────┬──────────────┐
        ▼              ▼                ▼              ▼
   scanner-sca   scanner-sast   scanner-container-iac  scanner-asm
                               │
                               ▼
                        notification-service → Slack / Jira / webhook
```

The gateway holds no business logic — if it starts to, that logic belongs in a service.

## Data flow

Two paths, and both matter.

**Discovery (continuous):** connectors sync on an interval → assets are upserted by `externalKey` → anything not seen this cycle is archived, not deleted → `ctem.asset.discovered` / `.updated`.

**Assessment (event-driven):** scan requested → planner selects assets the scanner actually applies to → jobs persisted → `ctem.scan.job.dispatched` → worker executes, uploads raw output → `ctem.finding.reported` → findings normalized, deduped by fingerprint, anything no longer reported auto-resolved → `ctem.finding.created/.updated` → risk scored → policy evaluated → `ctem.policy.violated` → notification. CI polls `GET /v1/scans/:id`; if a matching `fail_build` rule wins, `conclusion` is `failed`. Callers cannot POST that field.

## Tenancy

Every tenant table has `orgId`, RLS enabled with `FORCE`, and a `tenant_isolation` policy on `"orgId" = current_org_id()`. `current_org_id()` reads the `app.current_org_id` GUC and returns NULL when unset, so **an unscoped query returns zero rows** — the failure mode is an empty page, never another tenant's data.

Application code goes through `PrismaService.withOrg(orgId, fn)`, which opens a transaction and sets the GUC with `set_config(..., is_local => true)` so it is rolled back with the transaction. Connection pooling is therefore safe: the setting cannot leak to the next borrower.

The app connects as `ctem_app` (non-superuser, no `BYPASSRLS`). Migrations run as the owner. Cross-tenant work must call `unsafeCrossTenant(reason, fn)`, which logs the reason and is trivially greppable in review.

Vulnerability intelligence (`vulnerabilities`) is deliberately **not** tenant-scoped — it is a mirror of public data, readable by all, writable only by the feed ingester.

## Auth

1. Humans authenticate with the IdP and present a bearer JWT. Machine callers present a `ctem_pat_…` token.
2. The gateway verifies a JWT against the issuer's JWKS (`jose`, cached and auto-rotating), or POSTs a PAT to identity-service `/internal/tokens/verify`.
3. Org comes from the verified JWT `org_id` claim or the PAT record — never from the client. The gateway maps the role (JWT) or scopes (PAT) to a permission set and builds a `Principal`.
4. The principal is base64url-encoded and HMAC-signed into `x-ctem-principal` + `-signature`.
5. Downstream services verify the signature with `timingSafeEqual` and check route permissions.

In production this rides on mTLS inside the mesh, so the header cannot be injected from outside. Machine callers (CI, connectors) present `ctem_pat_…` tokens. The gateway POSTs the plaintext to identity-service `/internal/tokens/verify`; identity looks up the SHA-256 hash (via `verify_api_token`, because RLS has no org yet) and returns `{ orgId, tokenId, scopes, name }`. The gateway mints a service-account `Principal` from that record — org never comes from a client header, query, or body. A bad, missing, or unverifiable PAT fail-closes as 401.

## Risk model

```
base   = 0.30·severity + 0.25·exploitability + 0.25·exposure + 0.20·criticality
score  = min(100, base × validationMultiplier × 100)
```

- **severity** — CVSS-reconciled, not the scanner's self-reported label
- **exploitability** — EPSS, floored at 0.9 when the CVE is on CISA KEV
- **exposure** — internet-facing 1.0 / internal 0.5 / isolated 0.15, resolved through the asset graph
- **criticality** — business tier from asset ownership metadata
- **validation** — exploitable ×1.25, reachable ×1.1, not-reachable ×0.4, not-exploitable ×0.3

`GET /v1/findings/:id/risk` returns the factor breakdown. The seed data ships the same CVE (9.8, KEV) on two assets: 94 on the internet-facing tier-0 payments API, 41 on an isolated tier-3 batch job. That difference is the whole product thesis.

## Why microservices, honestly

The decision was made explicitly. The costs are real — distributed transactions become event choreography, local development needs five containers, and a schema change now touches several deploys. It is worth it here for three reasons:

1. Scanner workers are CPU- and IO-heavy, untrusted-code-adjacent, and need independent scaling and hard sandboxing. That alone forces a process boundary.
2. Ingest volume (findings) and query volume (dashboards) diverge by orders of magnitude.
3. Scanner blast radius: a SAST worker in an OOM loop must not take the API down.

The mitigation is that `@ctem/contracts` is the single source of truth for every payload on the wire, and every event is validated against its schema on both publish and consume. A shape change fails at the boundary rather than three services downstream.

## Build order

1. **Vulnerability feed mirror.** OSV (demand-driven) + NVD + GHSA ingest into `vulnerabilities`, with paged EPSS and KEV enrichment. SCA matches locally once a package has a sync row; live OSV is only the first-seen hop. A full bulk dump (to drop that hop) is optional later work.
2. **SCA depth.** Lockfile resolvers per ecosystem, real dependency paths, then reachability. Reachability is the single largest reduction in noise available.
3. **Cloud connectors.** GitHub and GitLab repository discovery is live (gitlab.com by default; self-hosted via explicit connector `baseUrl`). AWS inventory (EC2, S3, security groups, Elastic IPs → `cloud_resource`) is live via the same AssetConnector + scheduler. GCP/Azure are later.
4. **Web UI.** Thin Nx app at `apps/web`, served by the gateway. Login is a public OIDC client with PKCE: the browser redirects to compose Keycloak realm `ctem` and the callback stores the issued access-token JWT (never a PAT, never a password form). Assets, findings, finding risk + reachability, kick a scan, tenant policy editor (ordered notify, ticket, or fail-build rules). Notify is Slack; ticket is Jira in notification-service. Fail-build is the CI scan conclusion on `GET /v1/scans/:id` (PAT or JWT) — not GitHub Checks, not a client POST. Org is taken from the JWT (humans) or the PAT record (machines), never from the client.
5. **Distributed scheduling.** The discovery and scan schedulers use naive intervals; they need leader election or a JetStream-backed work queue before a second replica of either runs.
6. **Container layer scanning**, then IaC parsing, then ASM probing depth.
7. **Reachability + exploit validation.** This is what separates a CTEM platform from a vulnerability scanner with a dashboard.

## Known gaps in this scaffold

- Scanner internals beyond SCA SBOM ingest and lockfile resolution are stubbed: image layer walking, IaC parsing, port scanning. Remaining discovery connectors (Azure/GCP) are not built yet. AWS is inventory only — not a CSPM scanner.
- SCA source clone is allowlisted to `https://github.com/owner/repo` or `https://gitlab.com/owner/repo` from `cloneUrl` or a `github:` / `gitlab:` externalKey. Self-hosted GitLab clone/API is the connector `baseUrl` host (https only, no userinfo, no git@) — not `http_url_to_repo` and not extra tenant host fields. A refused/missing checkout, a private repo without a usable `env:GITHUB_*` / `env:GITLAB_*` credentialRef, or every lockfile parser failing throws — the job must not succeed with zero findings. `pom.xml` / `*.csproj` / `requirements.txt` are pinned-manifest fallbacks, not graphs.
- Policy `ticket` fans out to Jira Cloud (`{site}.atlassian.net`) via platform `env:JIRA_*` in notification-service. Slack still cannot ticket. Self-hosted Jira is later. Tenant config cannot set the host.
- Policy `fail_build` fails the CI-facing scan `conclusion` on GET. There is no GitHub Checks integration and no client write for conclusion. `block_deploy` is still later.
- Rate limiting is in-memory — correct for one replica only.
- SLA breach de-duplication is in-memory and resets on restart.
- No circuit breaker or retry budget on inter-service calls.
- `libs/db/prisma/migrations/000_rls` must be applied after the generated Prisma migration (`make db-migrate` does both in order).

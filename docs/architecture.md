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
| Cache/queue     | Redis                                               | Session and rate-limit state, short-lived scanner coordination, scheduler leader leases |
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
        ▼              ▼                ▼              ▼              ▼
   scanner-sca   scanner-sast   scanner-container-iac  scanner-asm  scanner-cspm
                               │
                               ▼
                        notification-service → Slack / Jira / webhook
```

The gateway holds no business logic — if it starts to, that logic belongs in a service.

## Data flow

Two paths, and both matter.

**Discovery (continuous):** the asset-service replica that holds `ctem:leader:discovery-schedule` syncs connectors on a 15-minute interval → assets are upserted by `externalKey` → anything not seen this cycle is archived, not deleted → `ctem.asset.discovered` / `.updated`. Manual `syncOrg` is not lease-gated.

**Scheduled assessment:** the orchestrator replica that holds `ctem:leader:scan-schedule` walks orgs every 5 minutes and dispatches due scanner cadences. Manual / webhook / CI `createScan` is not lease-gated. A second replica of either scheduler process requires Redis; if Redis is unreachable the interval path skips the tick rather than running on every replica.

**Gateway rate limit:** api-gateway consumes a Redis token bucket (`ctem:ratelimit:gw:{ip}`, 600 requests / 60s, keyed by `req.ip` only). A second gateway replica shares that counter; if Redis is unreachable the limiter fails closed with HTTP 429. `GET /health`, `/health/live`, and `/health/ready` are excluded so probes do not consume the budget or 429 when Redis is down.

**Assessment (event-driven):** scan requested → planner selects assets the scanner actually applies to → jobs persisted → `ctem.scan.job.dispatched` → worker executes, uploads raw output → `ctem.finding.reported` → findings normalized, deduped by fingerprint, anything no longer reported auto-resolved → `ctem.finding.created/.updated` → risk scored → policy evaluated → `ctem.policy.violated` → notification. CI polls `GET /v1/scans/:id`; if a matching `fail_build` rule wins, `conclusion` is `failed`. Deploy tooling polls the same GET for `deployConclusion`; if a matching `block_deploy` rule wins, that field is `blocked`. Callers cannot POST either field. On `ctem.scan.completed`, orchestrator may create/update one GitHub Check Run on `api.github.com` from the **same** `concludeScan` result when the scan carries a valid Checks context (`options.github.repository` + `sha`). Missing context skips Checks (log). Checks are additive — they do not replace GET `conclusion` and are not mapped from `block_deploy`. A sibling GitLab Commit Status publisher may POST one status on the allowlisted GitLab API (`gitlab.com` or the scan asset's GitLab connector `baseUrl`) from that same `concludeScan` result when `options.gitlab.projectId` + `sha` are present. GitLab statuses are additive, skip when context is missing, and are not mapped from `block_deploy`. Independently, orchestrator may create one GitHub Deployment status from the **same** `concludeDeploy` result when the scan carries `repository` + `deploymentId`. Missing context skips Deployments (log). Deployment statuses are additive — they do not replace GET `deployConclusion` and are not mapped from `fail_build`. A sibling GitLab Deployments publisher may **PUT** an existing GitLab Deployment (`options.gitlab.projectId` + `deploymentId`) on the allowlisted GitLab API from that same `concludeDeploy` result (`blocked` → `status=failed`, `allowed` → `status=success`). It never POSTs / creates a GitLab Deployment. Missing context skips the PUT (log). GitLab Deployment updates are additive and are not mapped from `fail_build`.

## Metering

Primary consumption unit is **`scan.kick`**: one accepted scan kick (one `Scan` row committed) is one flat unit. Orchestrator is the emitter of record. `createScan` (manual, API, webhook, CI) and scheduled cadence dispatch write a `scan_kicks` row in the **same transaction** as the scan insert. `scannerTypes` is a dimension, not a multiplier.

The gateway forwards `Idempotency-Key` and does not emit. Job dispatch, JetStream replay, findings, inventory, and digest pull do not emit. Before a scan id exists, a client `Idempotency-Key` or CI `external_id` / `externalId` is unique per org and returns the existing scan with no second row. Schedule ticks rely on the `ctem:leader:scan-schedule` lease plus that transactional insert; a later tick inside the cadence does not emit again. AuthZ or validation that fails before persist emits nothing. A kick that persists and then fails mid-dispatch still counts.

Source of truth for the SKU is the metering architecture note (2026-09-20, billable unit per scan kick). This slice does not add Stripe, a ledger, or x402.

Accepted kicks are queryable via `GET /v1/meters/scan-kicks` (`scan:read`, org from the token only): a filtered list plus `total` over `scan_kicks`. That read does not add Stripe, a ledger, or x402.

## Tenancy

Every tenant table has `orgId`, RLS enabled with `FORCE`, and a `tenant_isolation` policy on `"orgId" = current_org_id()`. `current_org_id()` reads the `app.current_org_id` GUC and returns NULL when unset, so **an unscoped query returns zero rows** — the failure mode is an empty page, never another tenant's data.

Application code goes through `PrismaService.withOrg(orgId, fn)`, which opens a transaction and sets the GUC with `set_config(..., is_local => true)` so it is rolled back with the transaction. Connection pooling is therefore safe: the setting cannot leak to the next borrower.

The app connects as `ctem_app` (non-superuser, no `BYPASSRLS`). Migrations run as the owner. Cross-tenant work must call `unsafeCrossTenant(reason, fn)`, which logs the reason and is trivially greppable in review.

Vulnerability intelligence (`vulnerabilities`) is deliberately **not** tenant-scoped — it is a mirror of public data, readable by all, writable only by the feed ingester.

## Auth

1. Humans authenticate with the IdP and present a bearer JWT. Machine callers present a `ctem_pat_…` token.
2. The gateway verifies a JWT against the issuer's JWKS (`jose`, cached and auto-rotating), or POSTs a PAT to identity-service `/internal/tokens/verify`.
3. Org comes from the verified JWT `org_id` claim or the PAT record — never from the client. For humans the gateway maps `claims.sub` → `users.id` via `idpSubject` (JIT upsert) and loads **Membership**; role and permissions come from Membership + `permissionsForRole`. JWT `roles` / realm roles are ignored. A missing or disabled membership is 403. Machine PATs still map scopes to permissions.
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
3. **Cloud connectors.** GitHub and GitLab repository discovery is live (gitlab.com by default; self-hosted via explicit connector `baseUrl`). AWS inventory (EC2, S3, security groups, Elastic IPs → `cloud_resource`), GCP inventory (GCE, GCS, firewalls, external IPs → `cloud_resource`), Azure inventory (VMs, storage accounts, NSGs, public IPs → `cloud_resource`), GHCR inventory (container packages → `container_image` keyed by digest), ECR inventory (repositories → `container_image` keyed by digest), GCR / Artifact Registry inventory (Docker repositories → `container_image` keyed by digest), ACR inventory (Azure Container Registry digests → `container_image` keyed by digest), Docker Hub inventory (Hub API digests → `container_image` keyed by digest), Quay inventory (Quay.io digests → `container_image` keyed by digest), Kubernetes inventory (managed EKS/GKE/AKS clusters → `kubernetes_workload`), and DNS inventory (`dns_enum` → `domain`) are live via the same AssetConnector + scheduler. The Kubernetes provider is one connector (`kubernetes`) with `config.cloud: aws|gcp|azure` — not three sibling providers. It talks only to `api.eks.{region}.amazonaws.com`, `container.googleapis.com`, and Azure ARM (`management.azure.com` + `login.microsoftonline.com`). Tenant `apiServerUrl` / kubeconfig `server` / `https://10.x:6443` are refused. Self-managed / on-prem kubeconfig is out. DNS inventory takes org-owned apex FQDNs in connector config and mints `dns:{fqdn}` domain assets from Certificate Transparency on exact host `crt.sh` (`https://crt.sh` port 443) plus the OS resolver (`resolve4` / `resolve6` / `resolveCname` / `resolveNs`). Tenant nameserver / DoH / AXFR / CT URL / wordlist keys are refused. Public A/AAAA land in `attributes.addresses` only — no `ip_range` mint, no ASM probe.
4. **Web UI.** Thin Nx app at `apps/web`, served by the gateway. Login is a public OIDC client with PKCE: the browser redirects to compose Keycloak realm `ctem` and the callback stores the issued access-token JWT (never a PAT, never a password form). Assets, findings, finding risk + reachability, kick a scan, tenant policy editor (ordered notify, ticket, fail-build, or block-deploy rules). Notify is Slack; ticket is Jira in notification-service. Fail-build is the CI scan conclusion on `GET /v1/scans/:id` (PAT or JWT); block-deploy is the independent `deployConclusion` on the same GET — callers cannot POST either field. An optional GitHub Check Run on `api.github.com` maps the same `concludeScan` result when Checks context is present. An optional GitLab Commit Status on the allowlisted GitLab API maps that same `concludeScan` result when GitLab CI context (`projectId` + `sha`) is present. An optional GitHub Deployment status maps `concludeDeploy` when Deployments context (`repository` + `deploymentId`) is present. An optional GitLab Deployment PUT maps `concludeDeploy` when GitLab Deployments context (`projectId` + `deploymentId`) is present — CTEM never creates the GitLab Deployment. Org is taken from the JWT (humans) or the PAT record (machines), never from the client.
5. **Distributed scheduling.** Redis leader leases in `@ctem/coordination` (`ctem:leader:scan-schedule`, `ctem:leader:discovery-schedule`) so a second replica of orchestrator or asset-service does not double-fire interval ticks. Manual kicks stay ungated. JetStream remains the job bus, not the scheduler control-plane.
6. **Container layer scanning**, then remaining IaC depth, then ASM probing depth. GHCR / ECR / GCR / ACR / Docker Hub / Quay digest pull is live. Kubernetes discovery inventories managed clusters only (not Deployments/Pods, not kube-apiserver). DNS inventory mints apex + under-apex `domain` assets (`provider=dns_enum`). ASM subdomain enumeration stays findings-only on existing apex `domain` assets (crt.sh JSON + OS `resolveNs`, no mint).
7. **Reachability + exploit validation.** First-party reachability covers JavaScript, Python, Go, and Rust (`crates.io` from `.rs`). This is what separates a CTEM platform from a vulnerability scanner with a dashboard.

## Known gaps in this scaffold

- Scanner internals beyond SCA SBOM ingest and lockfile resolution: IaC misconfig scanning is live; container image scanning pulls allowlisted GHCR / ECR / GCR / ACR / Docker Hub / Quay digests in-process (fail-closed on incomplete layer inventory). ASM probes a fixed port/TLS/HTTP set and, for apex `domain` assets only, enumerates subdomains via Certificate Transparency on exact host `crt.sh` (`https://crt.sh` port 443) plus OS `resolveNs` (no DoH, no tenant CT URL/wordlist/port list, max 200 names, 3 CT pages / 1 MiB / 8s per page). Truncated CT without a complete signal fails the job. Findings hang on the job's apex asset with `location` naming the host; the worker does not mint assets. DNS inventory (`provider=dns_enum`) is the minting counterpart: required `apex` / `apexes` FQDN labels, exact host `crt.sh` plus OS resolver, `kind=domain` / `source=dns_enum` / `externalKey=dns:{fqdn}`, ≤200 names/apex, leftover CT `rel=next` or size truncate fails the sync (no archiveStale on partial). Tenant recursive DNS / DoH / AXFR / CT URL / wordlist keys are refused. No credentialRef required; a present-but-unusable ref fails closed. Public A/AAAA stay in `attributes.addresses`; `ip_range` is not minted. AWS, GCP, and Azure inventory is live; CSPM (`cloud_posture`) evaluates inventoried `cloud_resource` assets read-only (public bucket / open SG class). GHCR discovery lists Packages REST on `api.github.com` only; ECR discovery lists the ECR JSON API on `api.ecr.{region}.amazonaws.com` only; GCR discovery lists Artifact Registry on `artifactregistry.googleapis.com` only (`kind=container_image` / `source=gcr` / `externalKey=gcr:{project}/{location}/{repository}/{image}@sha256:<digest>`; no layer pull); ACR discovery lists ARM on `management.azure.com` plus the ARM-returned `{loginServer}` (`{name}.azurecr.io` only) for `/acr/v1/_catalog` and `/acr/v1/{repository}/_manifests` (`kind=container_image` / `source=acr` / `externalKey=acr:{subscriptionId}/{resourceGroup}/{registry}/{repository}@sha256:<digest>`; no layer pull; tenant cannot set loginServer / registryUrl / host); Docker Hub discovery lists Hub API on `hub.docker.com` only (`kind=container_image` / `source=dockerhub` / `externalKey=dockerhub:{namespace}/{repository}@sha256:<digest>`; no layer pull; tenant cannot set registry URL / hubUrl / index.docker.io); Quay discovery lists REST on exact host `quay.io` (`https://quay.io/api/v1/...` only) (`kind=container_image` / `source=quay` / `externalKey=quay:{namespace}/{repository}@sha256:<digest>`; tenant cannot set quayUrl / host / authority / baseUrl; no self-hosted Quay); layer pull is the container scanner on allowlisted `ghcr.io`, ECR `dkr.ecr`, Artifact Registry `*.pkg.dev`, `{registry}.azurecr.io`, Docker Hub `registry-1.docker.io` + `auth.docker.io`, and Quay `quay.io` (manifest + blob + `/v2/auth`; `env:QUAY_*` fail-closed). Kubernetes discovery (`provider=kubernetes`, `config.cloud=aws|gcp|azure`) lists managed clusters via EKS `api.eks.{region}.amazonaws.com`, GKE `container.googleapis.com`, and AKS ARM only. Exact set: `Cluster` (`namespace=_`). Deployments / StatefulSets / DaemonSets / CronJobs / Pods are out — those require a tenant kube-apiserver dial. Credentials are `env:AWS_*` / `env:GCP_*` / `env:AZURE_*` matching `cloud`. `kubernetes_workload` is not in `SCANNER_ASSET_KINDS.container` or `cloud_posture`.
- SCA source clone is allowlisted to `https://github.com/owner/repo` or `https://gitlab.com/owner/repo` from `cloneUrl` or a `github:` / `gitlab:` externalKey. Self-hosted GitLab clone/API is the connector `baseUrl` host (https only, no userinfo, no git@) — not `http_url_to_repo` and not extra tenant host fields. A refused/missing checkout, a private repo without a usable `env:GITHUB_*` / `env:GITLAB_*` credentialRef, or every lockfile parser failing throws — the job must not succeed with zero findings. `pom.xml` / `*.csproj` / `requirements.txt` are pinned-manifest fallbacks, not graphs. Python prefers poetry.lock → uv.lock / Pipfile.lock → requirements.txt. Java prefers in-repo CycloneDX → gradle.lockfile (+ pom direct hints) → pom.xml fallback.
- Policy `ticket` fans out to Jira Cloud (`{site}.atlassian.net`) via platform `env:JIRA_*` in notification-service. Slack still cannot ticket. Self-hosted Jira is later. Tenant config cannot set the host.
- Policy `fail_build` fails the CI-facing scan `conclusion` on GET (`concludeScan`). Policy `block_deploy` independently sets GET `deployConclusion` to `blocked` (`concludeDeploy`) — same matching math, not the same field. GitHub Checks are optional and additive: on terminal `scanCompleted`, orchestrator creates or PATCHes one Check Run on `https://api.github.com` when the scan carries `repository` + `sha` (under `options.github` or top-level allowlisted keys). `env:GITHUB_*` credentials (prefer the scan/asset integration ref; else platform `env:GITHUB_TOKEN`). Missing context or unusable credentials skip the Check (log) and leave GET conclusion alone. A second replica that publishes Checks still needs `GITHUB_*` plus context; identity is `name` + `head_sha` + `external_id=scanId` (create once, then PATCH). GitLab Commit Statuses are a sibling publisher of `concludeScan` (`failed` → `state=failed`, `passed` → `state=success`) when `options.gitlab.projectId` + `sha` are present; egress is HTTPS `gitlab.com` or the scan asset's GitLab connector `baseUrl` (tenant scan host keys are ignored); `env:GITLAB_*` (prefer the scan/asset integration ref; else `env:GITLAB_TOKEN`); GitLab has no PATCH for statuses, so the publisher lists then skips a duplicate POST when `description` already contains `scanId`. GitHub Deployment statuses are a sibling publisher of `concludeDeploy` (`blocked` → `failure`, `allowed` → `success`) when `repository` + `deploymentId` are present; GitHub has no PATCH for statuses, so the publisher lists then skips a duplicate POST when `description` already contains `scanId`. GitLab Deployments are a sibling publisher of `concludeDeploy` (`blocked` → `status=failed`, `allowed` → `status=success`) when `options.gitlab.projectId` + `deploymentId` are present; CTEM only PUTs that existing deployment (no POST create) and skips the PUT when GET already shows the same status. No GitHub Enterprise host. Client conclusion keys (`conclusion`, `deployConclusion`) stay refused. Checks and GitLab statuses stay mapped from `fail_build` only; GitHub and GitLab Deployment publishers stay mapped from `block_deploy` only. Environment protection / required-reviewers APIs and GitLab protected-environments / approval-rules write APIs are out.
- Gateway rate limiting is Redis-backed (`ctem:ratelimit:gw:{ip}`, 600/min). The in-memory bucket is gone; a second api-gateway replica needs Redis or every non-health request 429s (fail closed). Scheduler interval ticks are still lease-gated; a second orchestrator or asset-service replica also needs Redis.
- SLA breach notify-once is a durable claim on `findings.slaNotifiedAt` (atomic `UPDATE … WHERE slaNotifiedAt IS NULL`); Redis is not the source of truth.
- Circuit breaker + retry budget (`@ctem/resilience`) is wired on api-gateway `ServiceProxy` (gateway → identity / asset / orchestrator / findings / risk / reporting / notification) and on orchestrator third-party publisher egress (GitHub Checks, GitHub Deployments, GitLab Commit Statuses, GitLab Deployments) via the same `InternalHttpPolicy`. Open circuits fail fast: the gateway maps them to HTTP 503 (no empty/success payload); publisher egress logs and skips the publish (soft-fail preserved — the scan and GET conclusions stay unchanged). Retries are capped (`CTEM_CB_MAX_ATTEMPTS`, default 3) with exponential backoff + jitter, on timeouts and 502–504 only — not 4xx. Publisher circuits are per egress family (`egress:github-api`, `egress:gitlab-api`), not per scan or org. Notification-service Slack incoming webhooks and Jira Cloud issue create use the same `InternalHttpPolicy` on `egress:slack-webhook` and `egress:jira-api` with one attempt (no in-policy retry); an open circuit or a failed send throws so JetStream `notification-dispatch` naks and redelivers (`maxDeliver: 6`). Knobs are platform `CTEM_CB_*` env allowlist (fail closed on invalid); not tenant-writable. Gateway-auth identity verify, orchestrator → scanners (NATS), and other third-party egress (scanner pulls, inventory connectors) are unchanged.
- `libs/db/prisma/migrations/000_rls` must be applied after the generated Prisma migration (`make db-migrate` does both in order).

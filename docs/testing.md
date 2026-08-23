# Testing process

Three risks dominate this architecture and none of them are mockable: tenancy
(RLS + org propagation), event flows across services, and principal minting at
the gateway. The test tiers exist to keep those honest while staying fast
enough to run constantly.

## Tiers

| Tier | Files | Command | Needs | Budget |
| --- | --- | --- | --- | --- |
| 1. Unit | `*.spec.ts` | `make test` | nothing | seconds |
| 2–3. Integration | `*.int.spec.ts` | `make test-int` | `make infra` + `make db-migrate` | < 1 min |
| 4. E2E smoke | `tools/e2e/smoke.ts` | `make e2e` | `make dev` running | ~1 min |

**Unit** — pure logic: normalizers, dedup, scoring, contract schemas,
permission mappings. Colocated `*.spec.ts`, no infra, `passWithNoTests`.

**Integration** — real Postgres as the real roles. Two kinds live here:

- *Data-layer suites* like [rls.int.spec.ts](../libs/db/src/rls.int.spec.ts):
  fixtures are arranged with the owner (RLS-bypassing) connection, assertions
  run as `ctem_app` — the role services actually connect with. The RLS suite
  also sweeps the catalog: any table with an `orgId` column that lacks a
  forced `tenant_isolation` policy fails the build, so a future migration
  cannot silently add an unprotected tenant table.
- *Service suites* like the gateway guard test, which boots a minimal Nest app
  against a real JWKS-serving test IdP and talks to it over real HTTP.

Integration files run sequentially (`fileParallelism: false`) because they
share the dev database; keep suites self-contained by creating their own orgs
via `@ctem/testing` factories and deleting them in `afterAll`
(`deleteOrgCascade` — org deletion cascades to every tenant row).

**E2E smoke** — one scripted golden path against the live stack: health →
machine-token issuance → gateway PAT auth → asset registration → cross-org
isolation → permission denial → scan dispatch to completion → SBOM ingest
producing real findings for `express@4.17.1` → findings listing. The SBOM step
queries OSV, so it needs internet access; without it the step fails with a
message saying so.

## Shared helpers: `@ctem/testing`

- `applyTestEnv(overrides)` — set env vars and reset the cached config.
- `TestIdp` — an in-process OIDC issuer with a real JWKS endpoint; mints
  arbitrary JWTs (`idp.issueToken({ orgId, roles: ['auditor'] })`).
- `ownerClient()` / `appClient()` / `withOrg()` — the two database roles plus
  the org-scoped transaction helper.
- Factories: `createOrg`, `createUserWithMembership`, `createAsset`,
  `createFinding`, `deleteOrgCascade`, and `seedDemoOrg` — the same builder
  `make db-seed` uses, so demo data and test fixtures cannot drift.

## Definition of done for a change

1. New logic → unit tests next to it.
2. Touches the database or RLS → integration test asserting behavior **as
   `ctem_app`**, not as the owner.
3. Touches auth, tokens, or the principal → extend the gateway guard suite or
   the identity token suite.
4. Adds a tenant table → nothing to do; the RLS sweep fails until
   `libs/db/prisma/manual/000_rls.sql` covers it. Fix the SQL, not the test.
5. Changes the golden path (new endpoint in the flow, changed contract) →
   update `tools/e2e/smoke.ts`.

## Cadence

- `make test` — on every change, it's seconds.
- `make test-int` — before every commit.
- `make e2e` — before merging anything that crosses a service boundary.

## Conventions

- `*.int.spec.ts` is the only marker separating tiers; there is no separate
  directory tree. The unit config excludes the pattern, the int config
  includes only it.
- Never test isolation by adding `where: { orgId }` filters — that's the
  application-code habit RLS exists to replace. Arrange as owner, assert as
  `ctem_app`.
- Suites own their fixtures. Nothing may depend on the demo seed being
  present except the seed's own smoke usage.

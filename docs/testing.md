# Testing process

Three risks dominate this architecture and none of them are mockable: tenancy
(RLS + org propagation), event flows across services, and principal minting at
the gateway. The test tiers exist to keep those honest while staying fast
enough to run constantly.

## Tiers

| Tier             | Files                        | Command         | Needs                                          | Budget  |
| ---------------- | ---------------------------- | --------------- | ---------------------------------------------- | ------- |
| 1. Unit          | `*.spec.ts`                  | `make test`     | nothing                                        | seconds |
| 2–3. Integration | `*.int.spec.ts`              | `make test-int` | `make infra` + `make db-migrate`               | < 1 min |
| 4. E2E smoke     | `tools/e2e/smoke.ts`         | `make e2e`      | `make dev` running                             | ~1 min  |
| 5. UI smoke      | `apps/web-e2e/src/*.spec.ts` | `make test-ui`  | Docker; script starts infra + Keycloak + stack | ~2 min  |

**Unit** — pure logic: normalizers, dedup, scoring, contract schemas,
permission mappings. Colocated `*.spec.ts`, no infra, `passWithNoTests`.

**Integration** — real Postgres as the real roles. Two kinds live here:

- _Data-layer suites_ like [rls.int.spec.ts](../libs/db/src/rls.int.spec.ts):
  fixtures are arranged with the owner (RLS-bypassing) connection, assertions
  run as `ctem_app` — the role services actually connect with. The RLS suite
  also sweeps the catalog: any table with an `orgId` column that lacks a
  forced `tenant_isolation` policy fails the build, so a future migration
  cannot silently add an unprotected tenant table.
- _Service suites_ like the gateway guard test, which boots a minimal Nest app
  against a real JWKS-serving test IdP and talks to it over real HTTP.

Integration files run sequentially (`fileParallelism: false`) because they
share the dev database; keep suites self-contained by creating their own orgs
via `@ctem/testing` factories and deleting them in `afterAll`
(`deleteOrgCascade` — org deletion cascades to every tenant row).

**UI smoke (Phase A, Playwright Chromium)** — browser paths against the
gateway-served SPA and compose Keycloak. `make test-ui` (`tools/e2e/run-ui.sh`)
starts infra including Keycloak, applies migrations + RLS, seeds the demo org,
builds the web UI if `apps/web/dist` is missing, starts the control-plane
services when the gateway is not already healthy, installs Chromium if needed,
then runs `@ctem/web-e2e`. Specs cover Keycloak analyst/demo PKCE login (one
Sign-in button, no password/PAT/JWT paste, JWT in `sessionStorage`, org from
that JWT; two `completeAuthorization` calls with the same code must keep the
session), Findings Score Rail (six columns, every data row has `rail-*` and
`risk-band-*`, whole-row click → `/findings/:id`; skeleton / empty / error stay
distinct), a scan-kick smoke (Keycloak JWT session — not a PAT — POST
`/v1/scans` is 2xx and the UI shows a queued card with id; never an HTTP 500 /
Internal Server Error banner), and Members admin (Keycloak JWT with
`member:manage` lists, invites, setRole, and disable-with-confirm; without
`member:manage` write controls are absent). Empty tables or missing outcomes fail; they do
not pass. Traces and screenshots are retained on failure under
`apps/web-e2e/test-results`. This tier does **not** replace `make e2e`. CI runs
it as an optional `ui-smoke` job (Phase A) so a Playwright flake does not block
the required lint/unit/int/e2e job.

**E2E smoke** — one scripted golden path against the live stack: health →
machine-token issuance → gateway PAT auth → asset registration → cross-org
isolation → permission denial → source SCA fail-closed (no cloneable repo) → SBOM ingest
producing real findings for `express@4.17.1` → feed mirror population →
threat-intel refresh (KEV/EPSS) enriching those findings → GitHub discovery of a live fixture → org-B isolation after discovery → findings listing.
The SBOM and intel steps query OSV/CISA/FIRST, so they need internet access;
without it those steps fail with a message saying so. Policy editor steps cover
ordered notify/ticket/fail-build create/update, refuse block-deploy, org-B 404 on
another tenant's rule, CI GET conclusion failed from a matching fail_build rule,
and a valid PAT that cannot POST a failed conclusion.

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
3. Touches auth, tokens, or the principal → extend the gateway guard suite,
   the org-scoping/findings-tenancy suite, or the identity token suite.
   PAT verify must keep covering: org from the token record, fail-closed on
   a bad/missing PAT, and ignore a client-supplied org. The web client must
   never send an org id and must not expose a password field or a PAT in
   sessionStorage. Browser login must start authorize with PKCE and the
   callback must store the issued JWT, not a PAT.
4. Adds a tenant table → nothing to do; the RLS sweep fails until
   `libs/db/prisma/manual/000_rls.sql` covers it. Fix the SQL, not the test.
5. Changes the golden path (new endpoint in the flow, changed contract) →
   update `tools/e2e/smoke.ts`.
6. Changes browser login, the findings list Score Rail, scan kick, or Members
   admin → extend `apps/web-e2e` (Playwright). Do not treat an empty list or a
   missing scan / member outcome as a pass.

## Cadence

- `make test` — on every change, it's seconds.
- `make test-int` — before every commit.
- `make e2e` — before merging anything that crosses a service boundary.
- `make test-ui` — before merging UI auth, findings list, or scan-kick changes.
- **CI runs the required tiers on every PR** (`.github/workflows/ci.yml`): lint →
  build → unit → integration (ephemeral docker-compose Postgres with
  migrations + RLS) → the full stack booted from dist → e2e smoke. Playwright
  `ui-smoke` is an optional Phase A job (`continue-on-error`) and is not a
  merge gate yet. The pipeline _is_ the TEST environment — there is no
  standing test deployment.

## Conventions

- `*.int.spec.ts` is the only marker separating tiers; there is no separate
  directory tree. The unit config excludes the pattern, the int config
  includes only it.
- Never test isolation by adding `where: { orgId }` filters — that's the
  application-code habit RLS exists to replace. Arrange as owner, assert as
  `ctem_app`.
- Suites own their fixtures. Nothing may depend on the demo seed being
  present except the seed's own smoke usage.

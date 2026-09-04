# Single-VM test deployment

Runs the whole platform on one Linux box with Docker Compose, behind Caddy
with automatic TLS. This is a test environment: one replica per service,
MinIO instead of S3, dev dependencies left in the image so the same image can
migrate and seed.

## What you need

- A VM with Docker Engine + the compose plugin, 4 vCPU / 8 GB RAM minimum
  (Keycloak alone wants ~1 GB; twelve Node services plus Postgres add up).
- Two DNS A records pointing at it: the app (`CTEM_DOMAIN`) and Keycloak
  (`AUTH_DOMAIN`). Caddy needs both to resolve before it can get certificates.
- Inbound 80 and 443 only. Nothing else publishes a host port.
- Outbound egress to github.com, gitlab.com, ghcr.io, api.osv.dev, NVD, EPSS
  and CISA KEV, plus whatever ASM targets you point it at.

## First deploy

```sh
git clone <repo> ctem-platform && cd ctem-platform
cp .env.prod.example .env.prod      # fill in domains + secrets (openssl rand -hex 24)
make deploy-build                   # builds ctem-platform:local (~10 min cold)
make deploy-up                      # infra, Keycloak (imports the rendered realm), Caddy, services
make deploy-migrate                 # prisma migrate deploy + RLS + ctem_app password
make deploy-seed                    # demo org that matches the Keycloak analyst user
make deploy-ps                      # everything should report healthy
```

Then open `https://$CTEM_DOMAIN`, log in as `analyst` with `DEMO_PASSWORD`.

For curl: `OIDC_ISSUER=https://$AUTH_DOMAIN/realms/ctem OIDC_CLIENT_SECRET=$OIDC_API_CLIENT_SECRET DEMO_PASSWORD=... ./tools/demo-token.sh`.

## Updating

```sh
git pull && make deploy-build && make deploy-up && make deploy-migrate
```

`deploy-up` recreates only containers whose image or config changed.
`deploy-migrate` is idempotent (migrate deploy skips applied migrations, the
RLS script is written to be re-run).

## How the pieces fit

| Piece       | Where                             | Notes                                                                                                                                                                                                                |
| ----------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Image       | `deploy/docker/Dockerfile`        | One image; `APP=<apps dir>` picks the service. `VITE_OIDC_ISSUER` is baked into the web bundle at build time, which is why the image build reads `AUTH_DOMAIN`.                                                      |
| Stack       | `docker-compose.prod.yml`         | Shared env via YAML anchors; service URLs use compose DNS names.                                                                                                                                                     |
| Edge        | `deploy/caddy/Caddyfile`          | `CTEM_DOMAIN` → api-gateway (serves the SPA + API), `AUTH_DOMAIN` → Keycloak.                                                                                                                                        |
| Realm       | `deploy/keycloak/render-realm.py` | Rewrites the committed dev realm: public redirect URI, `sslRequired: external`, real `ctem-api` secret, real analyst password. Runs before Keycloak on every `up`, but Keycloak only imports into an empty database. |
| Keycloak DB | `deploy/postgres/10-keycloak.sh`  | Creates the `keycloak` role + database on first Postgres init.                                                                                                                                                       |

## Gotchas

- **Realm edits after first boot** go through the Keycloak admin console at
  `https://$AUTH_DOMAIN/admin`, or wipe the `keycloak` database and `up` again.
- **Services verify JWTs against the public issuer**, so the VM must be able to
  reach its own public hostname (hairpin). Every major cloud allows this; if
  JWKS fetches fail, that is the first thing to check.
- **The admin console and MinIO console are not exposed**; port-forward with
  `ssh -L 9001:localhost:9001` after temporarily publishing the port if needed.
- **Schedulers are single-instance.** Do not scale any service above one
  replica until leader election lands (README "Not yet built").
- **ASM probing** leaves the provider's IP space. Keep the allowlist tight and
  check the provider's acceptable-use policy.
- **Secrets with quotes or backslashes** break the SQL/JSON interpolation;
  stick to `openssl rand -hex`.

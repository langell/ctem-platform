#!/usr/bin/env bash
# Bring up infra + Keycloak + the control-plane stack, then run Playwright Phase A.
# Does not replace `make e2e` (PAT golden-path smoke).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "make test-ui needs Docker (compose Keycloak + Postgres)." >&2
  exit 1
fi

cp -n .env.example .env || true

echo "==> infra (Postgres, Redis, NATS, MinIO, Keycloak)"
docker compose up -d

echo "waiting for postgres..."
until docker compose exec -T postgres pg_isready -U ctem >/dev/null 2>&1; do sleep 1; done

echo "waiting for Keycloak realm ctem..."
kc_ok=0
for _ in $(seq 1 90); do
  if curl -sf -m 2 "http://localhost:8080/realms/ctem" >/dev/null 2>&1; then
    kc_ok=1
    break
  fi
  sleep 2
done
if [[ "$kc_ok" != "1" ]]; then
  echo "Keycloak realm ctem did not become ready at http://localhost:8080/realms/ctem" >&2
  docker compose logs --tail=80 keycloak >&2 || true
  exit 1
fi

echo "==> migrate + RLS + demo seed"
pnpm db:generate
pnpm db:deploy
docker compose exec -T postgres psql -U ctem -d ctem \
  -f /dev/stdin < libs/db/prisma/manual/000_rls.sql
pnpm db:seed

if [[ ! -f apps/api-gateway/dist/main.js ]]; then
  echo "==> build services"
  pnpm build
fi
if [[ ! -f apps/web/dist/index.html ]]; then
  echo "==> build web UI (gateway static)"
  pnpm build:web
fi

gateway_up() {
  curl -sf -m 2 "http://localhost:3000/health/live" >/dev/null 2>&1
}

if ! gateway_up; then
  echo "==> start control plane + scanners"
  pnpm nx run-many -t dev --parallel=16 --exclude=@ctem/web --exclude=@ctem/web-e2e \
    > /tmp/ctem-ui-stack.log 2>&1 &
  echo $! > /tmp/ctem-ui-stack.pid
  stack_ok=0
  for _ in $(seq 1 90); do
    all=1
    for port in 3000 3001 3002 3003 3004 3005 3006 3007; do
      curl -sf -m 2 "http://localhost:$port/health/live" >/dev/null 2>&1 || { all=0; break; }
    done
    if [[ "$all" == "1" ]]; then
      stack_ok=1
      break
    fi
    sleep 2
  done
  if [[ "$stack_ok" != "1" ]]; then
    echo "services failed to become healthy" >&2
    tail -150 /tmp/ctem-ui-stack.log >&2 || true
    exit 1
  fi
fi

if ! curl -sf -m 2 "http://localhost:3000/" >/dev/null; then
  echo "gateway is healthy but the web UI is missing — run pnpm build:web" >&2
  exit 1
fi

echo "==> Playwright Chromium"
if [[ -n "${CI:-}" ]]; then
  pnpm --filter @ctem/web-e2e exec playwright install --with-deps chromium
else
  pnpm --filter @ctem/web-e2e exec playwright install chromium
fi

pnpm --filter @ctem/web-e2e test:playwright

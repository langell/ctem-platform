#!/usr/bin/env bash
# dev.sh — fire up the full CTEM platform for local development
# Usage: ./dev.sh [--skip-infra] [--skip-migrate] [--seed]
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

log()     { echo -e "${CYAN}${BOLD}▶${RESET} $*"; }
success() { echo -e "${GREEN}${BOLD}✔${RESET} $*"; }
warn()    { echo -e "${YELLOW}${BOLD}⚠${RESET}  $*"; }
error()   { echo -e "${RED}${BOLD}✖${RESET} $*" >&2; }
dim()     { echo -e "${DIM}$*${RESET}"; }
banner()  {
  echo ""
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════╗"
  echo -e "║         CTEM Platform — dev mode         ║"
  echo -e "╚══════════════════════════════════════════╝${RESET}"
  echo ""
}

# ── Flags ────────────────────────────────────────────────────────────────────
SKIP_INFRA=false
SKIP_MIGRATE=false
RUN_SEED=false

for arg in "$@"; do
  case $arg in
    --skip-infra)    SKIP_INFRA=true ;;
    --skip-migrate)  SKIP_MIGRATE=true ;;
    --seed)          RUN_SEED=true ;;
    --help|-h)
      echo "Usage: ./dev.sh [--skip-infra] [--skip-migrate] [--seed]"
      echo ""
      echo "  --skip-infra    Skip starting Docker infra (if already running)"
      echo "  --skip-migrate  Skip Prisma migrations"
      echo "  --seed          Seed demo data after migration"
      exit 0
      ;;
    *) warn "Unknown flag: $arg" ;;
  esac
done

# ── Prerequisites ─────────────────────────────────────────────────────────────
check_prereqs() {
  local missing=()
  command -v docker  &>/dev/null || missing+=("docker")
  command -v node    &>/dev/null || missing+=("node (>=22)")
  command -v pnpm    &>/dev/null || missing+=("pnpm")

  if [[ ${#missing[@]} -gt 0 ]]; then
    error "Missing required tools: ${missing[*]}"
    exit 1
  fi

  local node_major
  node_major=$(node -e "process.stdout.write(process.versions.node.split('.')[0])")
  if [[ "$node_major" -lt 22 ]]; then
    error "Node.js ≥ 22 required (found v$(node -v))"
    exit 1
  fi
}

# ── .env ──────────────────────────────────────────────────────────────────────
ensure_env() {
  if [[ ! -f .env ]]; then
    warn ".env not found — copying from .env.example"
    cp .env.example .env
    success "Created .env (review and update secrets before sharing)"
  else
    dim ".env already exists — skipping copy"
  fi
}

# ── Install deps ──────────────────────────────────────────────────────────────
install_deps() {
  if [[ ! -d node_modules ]]; then
    log "Installing dependencies..."
    pnpm install --frozen-lockfile
    success "Dependencies installed"
  else
    dim "node_modules exists — skipping install"
  fi
}

# ── Infra ─────────────────────────────────────────────────────────────────────
start_infra() {
  if $SKIP_INFRA; then
    dim "Skipping infra (--skip-infra)"
    return
  fi

  log "Starting Docker infra (Postgres, Redis, NATS, MinIO, Keycloak)..."
  docker compose up -d

  # Wait for Postgres
  log "Waiting for Postgres to be ready..."
  local retries=30
  until docker compose exec -T postgres pg_isready -U ctem &>/dev/null; do
    retries=$((retries - 1))
    if [[ $retries -le 0 ]]; then
      error "Postgres did not become ready in time"
      exit 1
    fi
    sleep 1
  done
  success "Postgres is ready"

  # Wait for NATS
  log "Waiting for NATS to be ready..."
  retries=20
  until curl -sf http://localhost:8222/healthz &>/dev/null; do
    retries=$((retries - 1))
    if [[ $retries -le 0 ]]; then
      warn "NATS health check timed out — continuing anyway"
      break
    fi
    sleep 1
  done
  success "NATS is ready"
}

# ── DB ────────────────────────────────────────────────────────────────────────
run_migrations() {
  if $SKIP_MIGRATE; then
    dim "Skipping migrations (--skip-migrate)"
    return
  fi

  log "Generating Prisma client..."
  pnpm db:generate

  log "Running Prisma migrations..."
  pnpm db:migrate

  log "Applying row-level security policies..."
  local db_url="${DATABASE_URL:-postgresql://ctem:ctem@localhost:5432/ctem}"
  psql "$db_url" -f libs/db/prisma/migrations/000_rls/migration.sql

  success "Database is ready"
}

run_seed() {
  if ! $RUN_SEED; then return; fi
  log "Seeding demo data..."
  pnpm db:seed
  success "Demo data seeded"
}

# ── Print service table ───────────────────────────────────────────────────────
print_services() {
  echo ""
  echo -e "${BOLD}  Service endpoints${RESET}"
  echo -e "  ${DIM}─────────────────────────────────────────────────${RESET}"
  printf "  ${GREEN}%-28s${RESET} %s\n" "API Gateway"          "http://localhost:3000"
  printf "  ${GREEN}%-28s${RESET} %s\n" "Identity Service"     "http://localhost:3001"
  printf "  ${GREEN}%-28s${RESET} %s\n" "Asset Service"        "http://localhost:3002"
  printf "  ${GREEN}%-28s${RESET} %s\n" "Orchestrator Service" "http://localhost:3003"
  printf "  ${GREEN}%-28s${RESET} %s\n" "Findings Service"     "http://localhost:3004"
  printf "  ${GREEN}%-28s${RESET} %s\n" "Risk Service"         "http://localhost:3005"
  printf "  ${GREEN}%-28s${RESET} %s\n" "Reporting Service"    "http://localhost:3006"
  printf "  ${GREEN}%-28s${RESET} %s\n" "Notification Service" "http://localhost:3007"
  echo ""
  echo -e "  ${BOLD}  Infrastructure${RESET}"
  echo -e "  ${DIM}─────────────────────────────────────────────────${RESET}"
  printf "  ${CYAN}%-28s${RESET} %s\n" "Postgres"   "localhost:5432"
  printf "  ${CYAN}%-28s${RESET} %s\n" "Redis"      "localhost:6379"
  printf "  ${CYAN}%-28s${RESET} %s\n" "NATS"       "localhost:4222  (monitor: :8222)"
  printf "  ${CYAN}%-28s${RESET} %s\n" "MinIO UI"   "http://localhost:9001  (ctem / ctem-secret)"
  printf "  ${CYAN}%-28s${RESET} %s\n" "Keycloak"   "http://localhost:8080  (admin / admin)"
  printf "  ${CYAN}%-28s${RESET} %s\n" "Prisma Studio" "run: pnpm db:studio"
  echo ""
}

# ── Graceful shutdown ─────────────────────────────────────────────────────────
NX_PID=""
cleanup() {
  echo ""
  warn "Shutting down services..."
  if [[ -n "$NX_PID" ]]; then
    kill "$NX_PID" 2>/dev/null || true
    wait "$NX_PID" 2>/dev/null || true
  fi
  success "Services stopped. Infra containers left running."
  dim "  Stop infra with: docker compose down"
  dim "  Wipe volumes  with: docker compose down -v"
  echo ""
}
trap cleanup INT TERM

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  banner
  check_prereqs
  ensure_env

  # Load .env into the current shell so psql etc. pick up DATABASE_URL
  set -o allexport
  # shellcheck source=.env
  source .env
  set +o allexport

  install_deps
  start_infra
  run_migrations
  run_seed
  print_services

  log "Starting all services with file watching..."
  dim "  (Ctrl+C to stop)"
  echo ""

  pnpm nx run-many -t dev --parallel=12 &
  NX_PID=$!

  wait "$NX_PID"
}

main

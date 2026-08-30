#!/usr/bin/env bash
# Per-boot reconciliation for the CTEM platform development environment.
#
# Brings up everything the services need before the terminals entry launches
# them: the Docker daemon, the docker-compose infra (Postgres, Redis, NATS,
# MinIO, Keycloak), the database schema + row-level security, and the demo
# seed. It is idempotent — safe to run on every boot and safe to re-run.
set -euo pipefail

cd "$(dirname "$0")/.."

log() { echo "▶ $*"; }

# ── Docker daemon ─────────────────────────────────────────────────────────────
# The Cloud Agent VM has no systemd, so dockerd is launched directly. It uses
# the fuse-overlayfs storage driver (/etc/docker/daemon.json) because overlay2
# cannot mount overlay-on-overlay inside the nested VM.
start_dockerd() {
  if sudo docker info >/dev/null 2>&1; then
    log "docker daemon already running"
  else
    log "starting docker daemon (fuse-overlayfs)"
    sudo bash -c 'nohup dockerd >/tmp/dockerd.log 2>&1 &'
    for _ in $(seq 1 30); do
      sudo docker info >/dev/null 2>&1 && break
      sleep 1
    done
    if ! sudo docker info >/dev/null 2>&1; then
      echo "✖ docker daemon failed to start; last log lines:" >&2
      tail -20 /tmp/dockerd.log >&2 || true
      exit 1
    fi
    log "docker daemon is up"
  fi
  # Let the non-root user drive docker (and thus docker compose) without sudo.
  sudo chmod 666 /var/run/docker.sock 2>/dev/null || true
}

# ── Bridge networking ─────────────────────────────────────────────────────────
# Inside the nested VM, routing intra-bridge frames through netfilter drops
# container-to-container traffic (e.g. minio-init cannot reach minio). Disabling
# bridge-nf keeps that traffic on pure L2, which is all the infra needs.
fix_bridge_networking() {
  sudo modprobe br_netfilter 2>/dev/null || true
  if [[ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then
    sudo sysctl -w net.bridge.bridge-nf-call-iptables=0 \
                   net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1 || true
    log "bridge netfilter disabled (container-to-container L2)"
  fi
}

# ── Infra ─────────────────────────────────────────────────────────────────────
start_infra() {
  log "starting infra (postgres, redis, nats, minio, keycloak)"
  docker compose up -d

  log "waiting for postgres"
  for _ in $(seq 1 60); do
    docker compose exec -T postgres pg_isready -U ctem >/dev/null 2>&1 && break
    sleep 1
  done
  docker compose exec -T postgres pg_isready -U ctem >/dev/null 2>&1 \
    || { echo "✖ postgres did not become ready" >&2; exit 1; }
  log "postgres is ready"

  # The artifact bucket is created by the minio-init one-shot container. Force a
  # re-run so a fresh boot (or one where minio came up after init) still gets it.
  docker compose up -d --force-recreate minio-init >/dev/null 2>&1 || true
}

# ── Database ──────────────────────────────────────────────────────────────────
migrate_and_seed() {
  set -a; source .env; set +a

  log "applying prisma migrations"
  pnpm db:deploy

  log "applying row-level security policies"
  docker compose exec -T postgres psql -U ctem -d ctem \
    -f /dev/stdin < libs/db/prisma/manual/000_rls.sql >/dev/null

  log "seeding demo data (idempotent upsert)"
  pnpm db:seed
}

start_dockerd
fix_bridge_networking
start_infra
migrate_and_seed

echo "✔ start complete — infra up, database migrated and seeded"

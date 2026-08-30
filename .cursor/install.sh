#!/usr/bin/env bash
# Idempotent repository bootstrap for the CTEM platform.
#
# Runs after the source tree is checked out (at environment-build time when
# builds are enabled, otherwise during agent setup). It only prepares durable,
# source-derived state: dependencies, the generated Prisma client, the local
# .env, and the compiled dist/ the services run from. It must not start any
# long-lived process — Docker, infra and the services are handled by start.sh
# and the terminals entry.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "▶ pnpm install (frozen lockfile)"
pnpm install --frozen-lockfile

# Nx auto-loads .env into every task; the services read DATABASE_APP_URL from it
# so row-level security actually applies to them. Every value has a working
# default that matches docker-compose.yml.
if [[ ! -f .env ]]; then
  echo "▶ creating .env from .env.example"
  cp .env.example .env
fi

# The Prisma client is generated into gitignored libs/db/src/generated — nothing
# type-checks or builds until this runs. It needs no database.
echo "▶ prisma generate"
pnpm db:generate

echo "▶ build (typecheck + dist for the service stack)"
pnpm build

echo "✔ install complete"

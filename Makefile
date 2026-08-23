.PHONY: help setup infra infra-down build typecheck lint test test-int e2e db-migrate db-seed dev clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: ## Install dependencies, start infra, migrate and generate the client
	pnpm install
	cp -n .env.example .env || true
	$(MAKE) infra
	@echo "waiting for postgres..."
	@until docker compose exec -T postgres pg_isready -U ctem >/dev/null 2>&1; do sleep 1; done
	$(MAKE) db-migrate
	pnpm build

infra: ## Start Postgres, Redis, NATS, MinIO and Keycloak
	docker compose up -d

infra-down: ## Stop infra and delete volumes
	docker compose down -v

build: ## Compile all libs and services
	pnpm build

typecheck: ## Type-check without emitting
	pnpm typecheck

lint:
	pnpm lint

test: ## Unit tier: pure logic, no infra, seconds
	pnpm test

test-int: ## Integration tier: real Postgres/RLS, real crypto (needs `make infra` + db-migrate)
	pnpm test:int

e2e: ## Smoke the golden path against a running stack (needs `make dev` in another terminal)
	pnpm e2e

db-migrate: ## Apply Prisma migrations, then the row-level security policies
	pnpm db:generate
	pnpm db:migrate
	docker compose exec -T postgres psql -U ctem -d ctem \
	  -f /dev/stdin < libs/db/prisma/manual/000_rls.sql

db-seed: ## Seed a demo org with assets, findings and policies
	pnpm db:seed

dev: ## Build once, then run every service from dist with rebuild-and-restart watch (needs infra up)
	pnpm build
	pnpm exec tsc -b tsconfig.build.json --watch --preserveWatchOutput & \
	  TSC_PID=$$!; \
	  pnpm nx run-many -t dev --parallel=12; \
	  kill $$TSC_PID 2>/dev/null

clean:
	pnpm build:clean
	rm -rf node_modules .nx **/dist

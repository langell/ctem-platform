.PHONY: help setup infra infra-down build typecheck lint test test-int e2e db-migrate db-seed demo-token dev clean deploy-build deploy-up deploy-down deploy-migrate deploy-seed deploy-logs deploy-ps

COMPOSE_PROD = docker compose --env-file .env.prod -f docker-compose.prod.yml

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

build: ## Compile all libs and services, then the web UI
	pnpm build
	pnpm build:web

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

demo-token: ## Print a JWT for the seeded demo org (curl / API; browser login is Keycloak)
	@./tools/demo-token.sh

dev: ## Build once, then run every service from dist with rebuild-and-restart watch (needs infra up)
	pnpm build
	pnpm build:web
	pnpm exec tsc -b tsconfig.build.json --watch --preserveWatchOutput & \
	  TSC_PID=$$!; \
	pnpm nx run-many -t dev --parallel=16 --exclude=@ctem/web; \
	  kill $$TSC_PID 2>/dev/null

clean:
	pnpm build:clean
	rm -rf node_modules .nx **/dist

# ---- single-VM test environment (docker-compose.prod.yml, see deploy/README.md)

deploy-build: ## Build the platform image (needs .env.prod for AUTH_DOMAIN)
	$(COMPOSE_PROD) build

deploy-up: ## Start infra, Keycloak, Caddy and every service
	$(COMPOSE_PROD) up -d --remove-orphans

deploy-down: ## Stop the stack (volumes are kept)
	$(COMPOSE_PROD) down

deploy-migrate: ## Prisma migrate deploy, then RLS policies and the ctem_app password
	$(COMPOSE_PROD) run --rm migrate
	$(COMPOSE_PROD) exec -T postgres psql -v ON_ERROR_STOP=1 -U ctem -d ctem \
	  -f /dev/stdin < libs/db/prisma/manual/000_rls.sql
	$(COMPOSE_PROD) exec -T postgres sh -s < deploy/postgres/set-app-password.sh

deploy-seed: ## Seed the demo org into the VM database
	$(COMPOSE_PROD) run --rm seed

deploy-logs: ## Tail all service logs
	$(COMPOSE_PROD) logs -f --tail=200

deploy-ps: ## Show container status and health
	$(COMPOSE_PROD) ps

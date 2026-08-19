.PHONY: help setup infra infra-down build typecheck lint test db-migrate db-seed dev clean

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

test:
	pnpm test

db-migrate: ## Apply Prisma migrations, then the row-level security policies
	pnpm db:generate
	pnpm db:migrate
	psql "$${DATABASE_URL:-postgresql://ctem:ctem@localhost:5432/ctem}" \
	  -f libs/db/prisma/migrations/000_rls/migration.sql

db-seed: ## Seed a demo org with assets, findings and policies
	pnpm db:seed

dev: ## Run every service with file watching (needs infra up)
	pnpm nx run-many -t dev --parallel=12

clean:
	pnpm build:clean
	rm -rf node_modules .nx **/dist

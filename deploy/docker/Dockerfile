# One image for every CTEM service. APP selects which apps/<name>/dist/main.js
# runs (see entrypoint.sh). Build from the repo root:
#   docker build -f deploy/docker/Dockerfile --build-arg VITE_OIDC_ISSUER=... .
#
# Debian slim rather than Alpine: Prisma's query engine wants glibc + OpenSSL 3.
# git is required by the SCA scanner's repo checkout. Dev dependencies stay in
# the image on purpose so the same image runs `prisma migrate deploy` and the
# seed (tsx) — this is a test-environment image, not a minimal one.
FROM node:22-bookworm-slim

ARG VITE_OIDC_ISSUER=http://localhost:8080/realms/ctem
ENV NODE_ENV=production \
    VITE_OIDC_ISSUER=${VITE_OIDC_ISSUER} \
    PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH

RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && corepack enable \
 && corepack prepare pnpm@10.28.0 --activate

WORKDIR /app

# Layer the lockfile-only install so source edits do not re-download modules.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY apps ./apps
COPY libs ./libs
RUN find apps libs -mindepth 2 -maxdepth 2 ! -name package.json -exec rm -rf {} + \
 && NODE_ENV=development pnpm install --frozen-lockfile

COPY . .
RUN pnpm db:generate \
 && pnpm build \
 && pnpm build:web \
 && chown -R node:node /app

COPY deploy/docker/entrypoint.sh /usr/local/bin/ctem-entrypoint
RUN chmod +x /usr/local/bin/ctem-entrypoint

USER node
ENTRYPOINT ["ctem-entrypoint"]

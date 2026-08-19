# Single Dockerfile for every service; the target app is a build arg.
#   docker build --build-arg APP=api-gateway -f infra/docker/Dockerfile .
ARG NODE_VERSION=22-alpine

FROM node:${NODE_VERSION} AS base
RUN corepack enable
WORKDIR /app

FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps ./apps
COPY libs ./libs
# --frozen-lockfile so a drifted lockfile fails the build instead of silently
# resolving different versions than CI tested.
RUN pnpm install --frozen-lockfile

FROM deps AS build
COPY tsconfig.base.json tsconfig.build.json nx.json ./
COPY tools ./tools
RUN pnpm db:generate && pnpm build

FROM base AS runtime
ARG APP
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/libs ./libs
COPY --from=build /app/apps/${APP} ./apps/${APP}
COPY --from=build /app/package.json ./package.json

# Never run a scanner as root — it executes untrusted code by design.
USER node
ENV APP=${APP}
CMD ["sh", "-c", "node apps/${APP}/dist/main.js"]

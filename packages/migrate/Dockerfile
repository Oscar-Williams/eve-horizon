# Eve's migrate image: applies an app's SQL migrations (mounted at
# /migrations) to its database, then exits. Apps run it as a job service.
# Built from the repository root with the workspace lockfile and published
# with every platform release (scripts/release/image.sh).

# node:22-slim
ARG NODE_BASE_IMAGE=node@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
FROM ${NODE_BASE_IMAGE} AS base
RUN corepack enable
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/migrate/package.json ./packages/migrate/

FROM base AS build
RUN pnpm install --frozen-lockfile
COPY tsconfig.base.json ./
COPY packages/migrate/tsconfig.json ./packages/migrate/
COPY packages/migrate/src ./packages/migrate/src
RUN pnpm --filter @eve/migrate build

FROM base AS runtime-dependencies
RUN pnpm install --frozen-lockfile --prod

FROM ${NODE_BASE_IMAGE} AS production
ENV NODE_ENV=production
ENV MIGRATIONS_DIR=/migrations

# Build metadata (passed via --build-arg in CI)
ARG EVE_BUILD_VERSION=dev
ARG EVE_BUILD_SHA=unknown
ARG EVE_BUILD_TIME=unknown
ENV EVE_BUILD_VERSION=${EVE_BUILD_VERSION}
ENV EVE_BUILD_SHA=${EVE_BUILD_SHA}
ENV EVE_BUILD_TIME=${EVE_BUILD_TIME}

WORKDIR /app
COPY --from=runtime-dependencies /app/node_modules ./node_modules
COPY --from=runtime-dependencies /app/packages/migrate/node_modules ./packages/migrate/node_modules
COPY --from=build /app/packages/migrate/package.json ./packages/migrate/
COPY --from=build /app/packages/migrate/dist ./packages/migrate/dist
WORKDIR /app/packages/migrate

# The base image's `node` user, by number: the strict profile runs the job as
# the image's numeric user, and the kubelet cannot check runAsNonRoot against
# a name. The migrations are only read.
USER 1000:1000
CMD ["node", "dist/index.js"]

# node:22-alpine
FROM node@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build

WORKDIR /app
RUN corepack enable

COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/auth-react/package.json ./packages/auth-react/
COPY packages/auth/package.json ./packages/auth/
COPY apps/dashboard/package.json ./apps/dashboard/
RUN pnpm install --frozen-lockfile

COPY tsconfig.base.json ./
COPY packages/auth-react ./packages/auth-react
COPY packages/auth ./packages/auth
COPY apps/dashboard ./apps/dashboard

# Build auth then auth-react (auth-react re-exports auth's wire types)
RUN pnpm --filter @eve-horizon/auth build
RUN pnpm --filter @eve-horizon/auth-react build
RUN pnpm --filter @eve/dashboard build

# node:22-alpine
FROM node@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS production
WORKDIR /app

# Install production server dependencies, at exact versions
RUN npm install --no-save --ignore-scripts express@4.22.3 http-proxy-middleware@3.0.11

COPY --from=build /app/apps/dashboard/dist ./dist
COPY --from=build /app/apps/dashboard/server.js ./server.js
COPY --from=build /app/apps/dashboard/server ./server

EXPOSE 3200
CMD ["node", "server.js"]

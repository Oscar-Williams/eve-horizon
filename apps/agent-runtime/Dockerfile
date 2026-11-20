# node:22-slim
ARG NODE_BASE_IMAGE=node@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
FROM ${NODE_BASE_IMAGE} AS base
RUN corepack enable
WORKDIR /app

FROM base AS dependencies
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/agent-runtime/package.json ./apps/agent-runtime/
COPY packages/shared/package.json ./packages/shared/
COPY packages/db/package.json ./packages/db/
COPY packages/migrate/package.json ./packages/migrate/
COPY packages/eve-agent-cli/package.json ./packages/eve-agent-cli/
COPY packages/cli/package.json ./packages/cli/
RUN pnpm install --frozen-lockfile

FROM dependencies AS build
COPY . .
RUN pnpm --filter @eve/shared build \
    && pnpm --filter @eve/db build \
    && pnpm --filter @eve/migrate build \
    && pnpm --filter @eve/eve-agent-cli build \
    && pnpm --filter @eve-horizon/cli build \
    && pnpm --filter @eve/agent-runtime build

FROM base AS production

# kubectl and crane at exact versions, each checked against its sha256 (as
# published at dl.k8s.io/release/<version>/bin/linux/<arch>/kubectl.sha256 and
# in the go-containerregistry release's checksums.txt). Same values as the
# worker image.
ARG KUBECTL_VERSION=v1.37.2
ARG KUBECTL_SHA256_AMD64=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
ARG KUBECTL_SHA256_ARM64=fcc16f63186659d9722014b7e02d5fdd2d4e669cb8c0ab66365d7d3b8ba03509
ARG CRANE_VERSION=v0.20.3
ARG CRANE_SHA256_AMD64=36c67a932f489b3f2724b64af90b599a8ef2aa7b004872597373c0ad694dc059
ARG CRANE_SHA256_ARM64=d2235f7779cd39c6e40f43701d2512c997409f629fb53e621ede0d57d3f995e2
RUN set -eu; \
    apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git bash jq poppler-utils \
    && mkdir -p /home/node/.local/bin /home/node/.cc-mirror /opt/eve/workspaces /opt/eve/cache /opt/eve/state /opt/eve/toolchains \
    && chown -R node:node /home/node /opt/eve \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
         amd64) kubectl_sha256="$KUBECTL_SHA256_AMD64"; crane_arch=x86_64; crane_sha256="$CRANE_SHA256_AMD64" ;; \
         arm64) kubectl_sha256="$KUBECTL_SHA256_ARM64"; crane_arch=arm64; crane_sha256="$CRANE_SHA256_ARM64" ;; \
         *) echo "Unsupported arch: $arch" >&2; exit 1 ;; \
       esac \
    && curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl" \
    && echo "${kubectl_sha256}  /tmp/kubectl" | sha256sum -c - \
    && install -o root -g root -m 0755 /tmp/kubectl /usr/local/bin/kubectl \
    && curl -fsSLo /tmp/crane.tar.gz "https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_Linux_${crane_arch}.tar.gz" \
    && echo "${crane_sha256}  /tmp/crane.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/crane.tar.gz --no-same-owner -C /usr/local/bin crane \
    && chmod 0755 /usr/local/bin/crane \
    && rm -f /tmp/kubectl /tmp/crane.tar.gz \
    && rm -rf /var/lib/apt/lists/*

# --- Media processing tools (ffmpeg + whisper.cpp) ---
RUN set -eu; \
    apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg cmake make g++ \
    && git clone --depth 1 --branch v1.8.1 https://github.com/ggml-org/whisper.cpp /tmp/whisper-build \
    && cd /tmp/whisper-build \
    && cmake -B build -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=OFF -DBUILD_SHARED_LIBS=OFF \
    && cmake --build build -j$(nproc) --target whisper-cli \
    && cp build/bin/whisper-cli /usr/local/bin/whisper-cli \
    && mkdir -p /opt/whisper/models \
    && curl -L -o /opt/whisper/models/ggml-small.en.bin \
       https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-small.en.bin \
    && rm -rf /tmp/whisper-build \
    && apt-get purge -y --auto-remove cmake make g++ \
    && rm -rf /var/lib/apt/lists/*

# Harness CLIs at the exact versions locked in docker/harness-clis, installed
# without lifecycle scripts into the root-owned /opt/harness-clis (install.sh).
# The cc-mirror variants run the same Claude Code version as `claude`.
COPY docker/harness-clis/ /opt/harness-clis/
RUN set -eu; \
    /opt/harness-clis/install.sh; \
    claude_version="$(node -p 'require("/opt/harness-clis/package.json").dependencies["@anthropic-ai/claude-code"]')"; \
    (HOME=/home/node cc-mirror quick --provider mirror --name mclaude --claude-version "$claude_version" --yes --no-shell-env 2>/dev/null || true) \
    && (HOME=/home/node cc-mirror quick --provider zai --name zai --claude-version "$claude_version" --api-key "placeholder" --yes --no-shell-env 2>/dev/null || true) \
    && if [ -f /home/node/.cc-mirror/zai/config/settings.json ]; then \
         node -e "const fs=require('fs'); const f='/home/node/.cc-mirror/zai/config/settings.json'; const d=JSON.parse(fs.readFileSync(f)); delete d.env.ANTHROPIC_API_KEY; fs.writeFileSync(f,JSON.stringify(d,null,2));" 2>/dev/null || true; \
       fi \
    && if [ -x /home/node/.local/bin/mclaude ]; then ln -sf /home/node/.local/bin/mclaude /usr/local/bin/mclaude; \
       else printf '#!/bin/sh\nexec claude "$@"\n' > /usr/local/bin/mclaude && chmod +x /usr/local/bin/mclaude; fi \
    && if [ -x /home/node/.local/bin/zai ]; then ln -sf /home/node/.local/bin/zai /usr/local/bin/zai; \
       else printf '#!/bin/sh\nexec claude "$@"\n' > /usr/local/bin/zai && chmod +x /usr/local/bin/zai; fi \
    && chown -R node:node /home/node

ARG EVE_BUILD_VERSION=dev
ARG EVE_BUILD_SHA=unknown
ARG EVE_BUILD_TIME=unknown
ENV EVE_BUILD_VERSION=${EVE_BUILD_VERSION}
ENV EVE_BUILD_SHA=${EVE_BUILD_SHA}
ENV EVE_BUILD_TIME=${EVE_BUILD_TIME}
ENV DISABLE_TELEMETRY=1
ENV HOME=/home/node

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/apps/agent-runtime/node_modules ./apps/agent-runtime/node_modules
COPY --from=build /app/apps/agent-runtime/dist ./apps/agent-runtime/dist
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/db/dist ./packages/db/dist
COPY --from=build /app/packages/db/node_modules ./packages/db/node_modules
COPY --from=build /app/packages/db/package.json ./packages/db/
COPY --from=build /app/packages/db/migrations ./packages/db/migrations
COPY --from=build /app/packages/eve-agent-cli/dist ./packages/eve-agent-cli/dist
COPY --from=build /app/packages/eve-agent-cli/bin ./packages/eve-agent-cli/bin
COPY --from=build /app/packages/eve-agent-cli/node_modules ./packages/eve-agent-cli/node_modules
COPY --from=build /app/packages/eve-agent-cli/package.json ./packages/eve-agent-cli/
COPY --from=build /app/packages/cli/dist ./packages/cli/dist
COPY --from=build /app/packages/cli/bin ./packages/cli/bin
COPY --from=build /app/packages/cli/package.json ./packages/cli/
RUN ln -sf /app/packages/eve-agent-cli/bin/eve-agent-cli.js /usr/local/bin/eve-agent-cli
RUN ln -sf /app/packages/cli/bin/eve.js /usr/local/bin/eve
# Execute-only copy of node for the runtime itself. The kernel marks a process
# non-dumpable when it executes a binary its user cannot read, so harnesses
# (same UID) cannot read the runtime's environment from /proc/<pid>/environ or
# its memory. Harnesses keep the ordinary, readable /usr/local/bin/node.
RUN install -D -o root -g root -m 0711 /usr/local/bin/node /usr/local/libexec/eve-node
# Root-owned guards in the service's HOME. Node looks for modules missing from
# node_modules in ~/.node_modules and ~/.node_libraries, and the Kubernetes
# client reads ~/.kube/config before in-cluster config. Job code runs as the
# same UID and must not be able to create them; each holds a root-owned file so
# it cannot be removed and recreated either.
RUN for d in .node_modules .node_libraries .kube; do \
      mkdir -p "/home/node/$d" \
      && touch "/home/node/$d/.eve-root-owned" \
      && chown -R root:root "/home/node/$d" \
      && chmod 0755 "/home/node/$d" \
      && chmod 0444 "/home/node/$d/.eve-root-owned"; \
    done
ENV PATH="/home/node/.local/bin:/app/packages/eve-agent-cli/bin:${PATH}"
WORKDIR /app/apps/agent-runtime
USER node
# --disable-sigusr1: a harness (same UID) could otherwise open the inspector with SIGUSR1.
CMD ["/usr/local/libexec/eve-node", "--disable-sigusr1", "dist/main.js"]

FROM dependencies AS development
COPY . .
CMD ["pnpm", "--filter", "@eve/agent-runtime", "dev"]

FROM production AS runtime

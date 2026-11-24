# =============================================================================
# Eve Horizon Worker - Multi-Target Dockerfile with Toolchain Variants
# =============================================================================
#
# Build targets:
#   - base (recommended): Minimal Node.js runtime with app code, no extra toolchains
#   - media:     base + ffmpeg + whisper.cpp (audio/video processing)
#   - python:    base + Python 3 + pip + uv
#   - rust:      base + Rust (via rustup)
#   - java:      base + OpenJDK 21
#   - kotlin:    base + OpenJDK 21 + Kotlin
#   - full:      media + all toolchains (python + rust + java + kotlin)
#   - production: Alias for full
#   - development: Full toolchain + dev dependencies
#
# Usage:
#   docker build --target base -t eve-worker:base .  # Minimal (default for k8s)
#   docker build --target python -t eve-worker:python .
#   docker build --target rust -t eve-worker:rust .
#   docker build --target java -t eve-worker:java .
#   docker build --target kotlin -t eve-worker:kotlin .
#   docker build --target full -t eve-worker:full .
#   docker build --target production -t eve-worker:latest .
#   docker build --target development -t eve-worker:dev .
#
# =============================================================================

# node:22-slim
ARG NODE_BASE_IMAGE=node@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee

# gcr.io/kaniko-project/executor:v1.20.1
FROM gcr.io/kaniko-project/executor@sha256:c71116ee36be17b14026f853103f7fb695042a9b6a4b4ad9b70de0e65c5c94a1 AS kaniko
# moby/buildkit:v0.12.5
FROM moby/buildkit@sha256:449188623c7a8a3bd4f161c5d0ddf5cabbfb828f7eaadf9ed8111864b911a308 AS buildkit

# =============================================================================
# Stage: node-image
# Purpose: Minimal Node.js environment with essential system tools
# =============================================================================
FROM ${NODE_BASE_IMAGE} AS node-image

# Install essential system packages
# tini: Lightweight init system for proper zombie reaping and signal forwarding
# procps: Provides ps command for orphan process detection
# jq: JSON processing for scripts and harnesses
# gpg: Required for adding GitHub CLI apt repository
# poppler-utils: Provides pdftoppm for Claude Code's PDF Read tool (rasterises PDF pages to PNG for vision)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends git bash ca-certificates curl tini procps jq gpg poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# Execute-only copies of node and tini for the service's own processes.
# The kernel marks a process non-dumpable when it executes a binary its user
# cannot read, so job code running as the same UID (pipeline scripts, harnesses)
# cannot read the worker's environment from /proc/<pid>/environ or its memory.
# Jobs keep the ordinary, readable /usr/local/bin/node.
RUN install -D -o root -g root -m 0711 /usr/local/bin/node /usr/local/libexec/eve-node \
    && install -o root -g root -m 0711 /usr/bin/tini /usr/local/libexec/eve-tini

# Install GitHub CLI (gh) from official apt repository
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# Install kubectl for K8s operations, and crane for worker-local toolchain
# image extraction, at exact versions, each checked against its sha256 (as
# published at dl.k8s.io/release/<version>/bin/linux/<arch>/kubectl.sha256 and
# in the go-containerregistry release's checksums.txt). Same values as the
# agent-runtime image.
ARG KUBECTL_VERSION=v1.37.2
ARG KUBECTL_SHA256_AMD64=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
ARG KUBECTL_SHA256_ARM64=fcc16f63186659d9722014b7e02d5fdd2d4e669cb8c0ab66365d7d3b8ba03509
ARG CRANE_VERSION=v0.20.3
ARG CRANE_SHA256_AMD64=36c67a932f489b3f2724b64af90b599a8ef2aa7b004872597373c0ad694dc059
ARG CRANE_SHA256_ARM64=d2235f7779cd39c6e40f43701d2512c997409f629fb53e621ede0d57d3f995e2
RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) kubectl_sha256="$KUBECTL_SHA256_AMD64"; crane_arch=x86_64; crane_sha256="$CRANE_SHA256_AMD64" ;; \
      arm64) kubectl_sha256="$KUBECTL_SHA256_ARM64"; crane_arch=arm64; crane_sha256="$CRANE_SHA256_ARM64" ;; \
      *) echo "Unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl"; \
    echo "${kubectl_sha256}  /tmp/kubectl" | sha256sum -c -; \
    install -o root -g root -m 0755 /tmp/kubectl /usr/local/bin/kubectl; \
    curl -fsSLo /tmp/crane.tar.gz "https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_Linux_${crane_arch}.tar.gz"; \
    echo "${crane_sha256}  /tmp/crane.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/crane.tar.gz --no-same-owner -C /usr/local/bin crane; \
    chmod 0755 /usr/local/bin/crane; \
    rm -f /tmp/kubectl /tmp/crane.tar.gz

# Add kaniko executor for in-cluster image builds
COPY --from=kaniko /kaniko/executor /usr/local/bin/kaniko
# Add buildctl for in-cluster BuildKit builds
COPY --from=buildkit /usr/bin/buildctl /usr/local/bin/buildctl

RUN corepack enable

# ============================================================================
# NON-ROOT USER SETUP (Critical for K8s + Claude Code compatibility)
# ============================================================================
# Requirements:
#   - K8s: Pods run as non-root (uid 1000) for security
#   - Claude Code: yolo mode requires non-root user
#   - Docker Compose: More permissive, but we use same image
#
# The node:22-slim base image provides 'node' user (uid 1000, gid 1000).
# We pre-create ALL directories the worker might write to at runtime.
# This prevents permission errors in both K8s and Docker Compose.
#
# Directory purposes:
#   /home/node/.npm          - npm cache
#   /home/node/.cache        - general cache (pnpm, etc)
#   /home/node/.local/bin    - cc-mirror installs CLI tools here
#   /home/node/.local/share  - XDG data directory
#   /home/node/.claude       - claude code credentials
#   /home/node/.cc-mirror    - cc-mirror config
#   /home/node/.code         - every code auth
#   /home/node/.codex        - openai codex auth
#   /home/node/.config       - XDG config directory
#   /opt/eve/workspaces      - workspace root (volume mount point)
# ============================================================================
WORKDIR /app
ENV PATH="/home/node/.local/bin:${PATH}"
ENV HOME="/home/node"

# EVE base contract environment variables
ENV EVE_RUN_AS_UID=1000
ENV EVE_RUN_AS_GID=1000
ENV EVE_HOME=/home/node
ENV EVE_WORKSPACE_ROOT=/opt/eve/workspaces
ENV EVE_CACHE_ROOT=/opt/eve/cache
ENV EVE_STATE_ROOT=/opt/eve/state
ENV EVE_TOOLCHAIN_ROOT=/opt/eve/toolchains

# Cache routing environment variables
ENV XDG_CACHE_HOME=/opt/eve/cache
ENV XDG_CONFIG_HOME=/home/node/.config
ENV NPM_CONFIG_CACHE=/opt/eve/cache/npm
ENV COREPACK_HOME=/opt/eve/cache/corepack
ENV PNPM_HOME=/opt/eve/cache/pnpm
ENV PIP_CACHE_DIR=/opt/eve/cache/pip
ENV UV_CACHE_DIR=/opt/eve/cache/uv
ENV CCACHE_DIR=/opt/eve/cache/ccache

# Disable skills.sh telemetry in worker environment
ENV DISABLE_TELEMETRY=1

# =============================================================================
# Stage: dependencies
# Purpose: Install pnpm dependencies (cached layer)
# =============================================================================
FROM node-image AS dependencies
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/worker/package.json ./apps/worker/
COPY packages/shared/package.json ./packages/shared/
COPY packages/db/package.json ./packages/db/
COPY packages/migrate/package.json ./packages/migrate/
COPY packages/eve-agent-cli/package.json ./packages/eve-agent-cli/
COPY packages/cli/package.json ./packages/cli/
RUN pnpm install --frozen-lockfile

# =============================================================================
# Stage: build
# Purpose: Build the application from source
# =============================================================================
FROM dependencies AS build
COPY . .
RUN pnpm --filter @eve/shared build \
    && pnpm --filter @eve/db build \
    && pnpm --filter @eve/migrate build \
    && pnpm --filter @eve/eve-agent-cli build \
    && pnpm --filter @eve-horizon/cli build \
    && pnpm --filter @eve/worker build

# =============================================================================
# Stage: runtime-setup
# Purpose: Common runtime setup shared by all toolchain variants
#          Includes global npm packages, directories, git config, entrypoints
#          Does NOT include app code (added in base stage)
# =============================================================================
FROM node-image AS runtime-setup

# =============================================================================
# Harness Selection (customize via --build-arg)
# =============================================================================
# Each harness can be enabled/disabled independently:
#   docker build --build-arg INSTALL_CLAUDE=false --build-arg INSTALL_CODEX=false ...
#
# Harness sizes (approximate):
#   - gemini-cli:  440MB
#   - codex:       355MB
#   - cc-mirror:    92MB (multi-harness router, recommended)
#   - code:         88MB
#   - claude-code:  84MB
#   - skills:        ~4MB (skill management, skills.sh)
# =============================================================================
ARG INSTALL_CLAUDE=true
ARG INSTALL_CODEX=true
ARG INSTALL_GEMINI=true
ARG INSTALL_CODE=true
ARG INSTALL_PI=true
ARG INSTALL_MIRROR=true
ARG INSTALL_SKILLS=true

# Harness CLIs at the exact versions locked in docker/harness-clis, installed
# as root without lifecycle scripts into the root-owned /opt/harness-clis
# (install.sh reads the INSTALL_* args above).
COPY docker/harness-clis/ /opt/harness-clis/
RUN /opt/harness-clis/install.sh

# Create cc-mirror variants (mclaude, zai) for harness invocation, on the same
# Claude Code version as `claude`. A variant that cannot be built fails the
# image build: the entrypoint installs nothing at start, so a variant missing
# from the image would leave its harness unavailable.
# Note: This runs as root but creates files in /home/node/.cc-mirror and /home/node/.local/bin
# The zai API key is stripped from settings.json after creation - keys are passed via env at runtime
# Without cc-mirror (INSTALL_MIRROR=false), mclaude is a shim for claude.
RUN set -eu; \
    if command -v cc-mirror >/dev/null 2>&1; then \
      claude_version="$(node -p 'require("/opt/harness-clis/package.json").dependencies["@anthropic-ai/claude-code"]')"; \
      HOME=/home/node cc-mirror quick --provider mirror --name mclaude --claude-version "$claude_version" --no-tweak --yes --no-shell-env; \
      # Z.ai provider (GLM models). cc-mirror needs an API key to create the
      # variant; the placeholder is stripped so the runtime env var takes
      # precedence (the wrapper exports settings.json env vars over it).
      HOME=/home/node cc-mirror quick --provider zai --name zai --claude-version "$claude_version" --no-tweak --api-key "placeholder" --yes --no-shell-env; \
      node -e "const fs=require('fs'); const f='/home/node/.cc-mirror/zai/config/settings.json'; const d=JSON.parse(fs.readFileSync(f)); delete d.env.ANTHROPIC_API_KEY; fs.writeFileSync(f,JSON.stringify(d,null,2));"; \
      test -x /home/node/.local/bin/mclaude; \
      test -x /home/node/.local/bin/zai; \
      chown -R node:node /home/node/.cc-mirror /home/node/.local; \
    elif command -v claude >/dev/null 2>&1; then \
      printf '#!/bin/sh\nexec claude "$@"\n' > /usr/local/bin/mclaude && chmod +x /usr/local/bin/mclaude; \
    fi

# Pre-create ALL directories node user might write to (see directory list above)
# This single command ensures K8s and Docker Compose compatibility
RUN mkdir -p \
    /opt/eve/workspaces \
    /opt/eve/cache \
    /opt/eve/state \
    /opt/eve/toolchains \
    /opt/eve/cache/npm \
    /opt/eve/cache/corepack \
    /opt/eve/cache/pnpm \
    /opt/eve/cache/pip \
    /opt/eve/cache/uv \
    /opt/eve/cache/ccache \
    /kaniko \
    /home/node/.npm \
    /home/node/.cache \
    /home/node/.local/bin \
    /home/node/.local/share \
    /home/node/.claude \
    /home/node/.cc-mirror \
    /home/node/.code \
    /home/node/.codex \
    /home/node/.config \
    /home/node/.cargo \
    /home/node/.rustup \
    /home/node/.sdkman \
    && chown -R node:node /opt/eve /home/node

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

# kubectl's in-cluster kubeconfig (see the file): with the worker's
# --request-timeout, kubectl does not use in-cluster credentials by itself.
# Root-owned and read-only, because job code
# runs as the worker's user and must not be able to repoint it.
COPY docker/worker/in-cluster.kubeconfig /etc/eve/kube/in-cluster.kubeconfig
RUN chown -R root:root /etc/eve/kube \
    && chmod 0755 /etc/eve/kube \
    && chmod 0444 /etc/eve/kube/in-cluster.kubeconfig

# Configure git identity for automated commits (eve-worker skills install)
RUN git config --system user.email "eve-worker@eve-horizon.local" \
    && git config --system user.name "Eve Worker"

# Copy entrypoint and management scripts
COPY docker/worker/entrypoint.sh /usr/local/bin/eve-worker-entrypoint
COPY docker/worker/eve-skills /usr/local/bin/eve-skills
COPY docker/worker/orphan-reaper.sh /usr/local/bin/orphan-reaper
RUN chmod +x /usr/local/bin/eve-worker-entrypoint /usr/local/bin/eve-skills /usr/local/bin/orphan-reaper

# =============================================================================
# Stage: base
# Purpose: Minimal runtime with Node.js + app code (no extra toolchains)
#          This is the smallest complete worker image and the foundation
#          for all toolchain variants (python, rust, java, full)
# =============================================================================
FROM runtime-setup AS base

# Copy app code from build stage. It stays root-owned: job code runs as `node`
# and must not be able to modify the service it can later make restart.
USER root
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/apps/worker/node_modules ./apps/worker/node_modules
COPY --from=build /app/apps/worker/dist ./apps/worker/dist
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

# Link CLIs globally
RUN ln -s /app/packages/cli/bin/eve.js /usr/local/bin/eve

WORKDIR /app/apps/worker
USER node
# Use tini as init system for proper zombie reaping and signal forwarding
# This prevents orphaned processes from accumulating and exhausting resources
ENTRYPOINT ["/usr/local/libexec/eve-tini", "--", "/usr/local/bin/eve-worker-entrypoint"]
# --disable-sigusr1: a same-UID job could otherwise open the inspector with SIGUSR1.
CMD ["/usr/local/libexec/eve-node", "--disable-sigusr1", "dist/main.js"]

# =============================================================================
# Stage: media
# Purpose: Runtime with ffmpeg + whisper.cpp for audio/video processing
# =============================================================================
FROM base AS media

USER root

# ffmpeg: universal audio/video demuxing, decoding, conversion
# cmake + g++: build whisper.cpp from source
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg cmake make g++ \
    && rm -rf /var/lib/apt/lists/*

# whisper.cpp v1.8.1: CPU-based speech-to-text (pinned for reproducibility)
RUN git clone --depth 1 --branch v1.8.1 https://github.com/ggml-org/whisper.cpp /tmp/whisper-build \
    && cd /tmp/whisper-build \
    && cmake -B build -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=OFF -DBUILD_SHARED_LIBS=OFF \
    && cmake --build build -j$(nproc) --target whisper-cli \
    && cp build/bin/whisper-cli /usr/local/bin/whisper-cli \
    && mkdir -p /opt/whisper/models \
    && rm -rf /tmp/whisper-build

# Download small.en model (~150 MB, English-only, good speed/quality balance)
RUN curl -L -o /opt/whisper/models/ggml-small.en.bin \
    https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-small.en.bin

# Clean up build tools (keep ffmpeg runtime)
RUN apt-get purge -y --auto-remove cmake make g++ \
    && rm -rf /var/lib/apt/lists/*

USER node

# =============================================================================
# Stage: python
# Purpose: Runtime with Python 3 + pip + uv toolchain
# Note: Uses system Python (3.11 on Debian Bookworm)
# =============================================================================
FROM base AS python

# Install Python toolchain as root
USER root
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
       python3 \
       python3-pip \
       python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages uv==0.13.7

# Set Python environment variables
ENV PYTHON_HOME=/usr
ENV PATH="${PYTHON_HOME}/bin:${PATH}"

# App code inherited from base stage
USER node

# =============================================================================
# Stage: rust
# Purpose: Runtime with Rust toolchain (via rustup, user-level install)
# =============================================================================
FROM base AS rust

# Install Rust toolchain as node user (rustup user-level install)
USER node
ENV RUSTUP_HOME=/home/node/.rustup
ENV CARGO_HOME=/home/node/.cargo
ENV PATH="${CARGO_HOME}/bin:${PATH}"

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable \
    && . "${CARGO_HOME}/env" \
    && rustup component add rustfmt clippy \
    && rustup component remove rust-docs

# App code inherited from base stage

# =============================================================================
# Stage: java
# Purpose: Runtime with OpenJDK 21 toolchain
# =============================================================================
FROM base AS java

# Install Java toolchain as root
# Note: OpenJDK 21 requires Adoptium (Eclipse Temurin) repository on Debian Bookworm
USER root
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
       wget apt-transport-https gpg unzip \
    && wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor -o /etc/apt/keyrings/adoptium.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb $(cat /etc/os-release | grep VERSION_CODENAME | cut -d= -f2) main" > /etc/apt/sources.list.d/adoptium.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       temurin-21-jdk \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/lib/jvm/temurin-21-jdk-* /usr/lib/jvm/temurin-21

# Set Java environment variables (symlink handles multi-arch)
ENV JAVA_HOME=/usr/lib/jvm/temurin-21
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# App code inherited from base stage
USER node

# =============================================================================
# Stage: kotlin
# Purpose: Runtime with OpenJDK 21 + Kotlin toolchain
# =============================================================================
FROM java AS kotlin

# Install Kotlin toolchain as root (via direct download since SDKMAN requires bash)
USER root

# Install Kotlin compiler directly
ARG KOTLIN_VERSION=2.0.21
RUN curl -L -o /tmp/kotlin.zip "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip" \
    && unzip /tmp/kotlin.zip -d /opt \
    && rm /tmp/kotlin.zip \
    && ln -s /opt/kotlinc/bin/kotlin /usr/local/bin/kotlin \
    && ln -s /opt/kotlinc/bin/kotlinc /usr/local/bin/kotlinc \
    && chown -R node:node /opt/kotlinc

# Set Kotlin environment variables
ENV KOTLIN_HOME=/opt/kotlinc
ENV PATH="${KOTLIN_HOME}/bin:${PATH}"

WORKDIR /app/apps/worker
USER node
ENTRYPOINT ["/usr/local/libexec/eve-tini", "--", "/usr/local/bin/eve-worker-entrypoint"]
# --disable-sigusr1: a same-UID job could otherwise open the inspector with SIGUSR1.
CMD ["/usr/local/libexec/eve-node", "--disable-sigusr1", "dist/main.js"]

# =============================================================================
# Stage: full
# Purpose: Runtime with ALL toolchains (Python + Rust + Java + Kotlin) + media tools
# =============================================================================
FROM media AS full

# Install all toolchains as root
USER root

# Python 3 + pip + uv (uses system Python 3.11 on Debian Bookworm)
# Java 21 via Adoptium (Eclipse Temurin) since OpenJDK 21 not in Debian Bookworm
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
       python3 \
       python3-pip \
       python3-venv \
       wget apt-transport-https gpg \
       unzip \
    && pip3 install --break-system-packages uv==0.13.7 \
    && wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor -o /etc/apt/keyrings/adoptium.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb $(cat /etc/os-release | grep VERSION_CODENAME | cut -d= -f2) main" > /etc/apt/sources.list.d/adoptium.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       temurin-21-jdk \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/lib/jvm/temurin-21-jdk-* /usr/lib/jvm/temurin-21

# Set Python and Java environment variables (symlink handles multi-arch)
ENV PYTHON_HOME=/usr
ENV JAVA_HOME=/usr/lib/jvm/temurin-21
ENV PATH="${JAVA_HOME}/bin:${PYTHON_HOME}/bin:${PATH}"

# Install Kotlin compiler directly
ARG KOTLIN_VERSION=2.0.21
RUN curl -L -o /tmp/kotlin.zip "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip" \
    && unzip /tmp/kotlin.zip -d /opt \
    && rm /tmp/kotlin.zip \
    && ln -s /opt/kotlinc/bin/kotlin /usr/local/bin/kotlin \
    && ln -s /opt/kotlinc/bin/kotlinc /usr/local/bin/kotlinc \
    && chown -R node:node /opt/kotlinc

# Set Kotlin environment variables
ENV KOTLIN_HOME=/opt/kotlinc

# Install Rust toolchain as node user
USER node
ENV RUSTUP_HOME=/home/node/.rustup
ENV CARGO_HOME=/home/node/.cargo
ENV PATH="${CARGO_HOME}/bin:${KOTLIN_HOME}/bin:${PATH}"

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable \
    && . "${CARGO_HOME}/env" \
    && rustup component add rustfmt clippy \
    && rustup component remove rust-docs

# App code inherited from base stage

# =============================================================================
# Stage: production
# Purpose: Production image (alias for full toolchain)
# =============================================================================
FROM full AS production

# Build metadata (passed via --build-arg in CI)
ARG EVE_BUILD_VERSION=dev
ARG EVE_BUILD_SHA=unknown
ARG EVE_BUILD_TIME=unknown
ENV EVE_BUILD_VERSION=${EVE_BUILD_VERSION}
ENV EVE_BUILD_SHA=${EVE_BUILD_SHA}
ENV EVE_BUILD_TIME=${EVE_BUILD_TIME}

# Production is simply the full toolchain image with build metadata

# =============================================================================
# Stage: development
# Purpose: Development image with full toolchains + dev dependencies
# =============================================================================
FROM dependencies AS development

# Harness CLIs as in the runtime stages (docker/harness-clis)
COPY docker/harness-clis/ /opt/harness-clis/
RUN /opt/harness-clis/install.sh

# Pre-create ALL directories node user might write to (see directory list in base stage)
# This single command ensures K8s and Docker Compose compatibility
RUN mkdir -p \
    /opt/eve/workspaces \
    /opt/eve/cache \
    /opt/eve/state \
    /opt/eve/toolchains \
    /opt/eve/cache/npm \
    /opt/eve/cache/corepack \
    /opt/eve/cache/pnpm \
    /opt/eve/cache/pip \
    /opt/eve/cache/uv \
    /opt/eve/cache/ccache \
    /kaniko \
    /home/node/.npm \
    /home/node/.cache \
    /home/node/.local/bin \
    /home/node/.local/share \
    /home/node/.claude \
    /home/node/.cc-mirror \
    /home/node/.code \
    /home/node/.codex \
    /home/node/.config \
    /home/node/.cargo \
    /home/node/.rustup \
    /home/node/.sdkman \
    && chown -R node:node /opt/eve /home/node

# Install all toolchains for development
# Python 3 + pip + uv (uses system Python 3.11 on Debian Bookworm)
# Java 21 via Adoptium (Eclipse Temurin) since OpenJDK 21 not in Debian Bookworm
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
       python3 \
       python3-pip \
       python3-venv \
       wget apt-transport-https gpg \
       unzip \
    && pip3 install --break-system-packages uv==0.13.7 \
    && wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor -o /etc/apt/keyrings/adoptium.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb $(cat /etc/os-release | grep VERSION_CODENAME | cut -d= -f2) main" > /etc/apt/sources.list.d/adoptium.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       temurin-21-jdk \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/lib/jvm/temurin-21-jdk-* /usr/lib/jvm/temurin-21

# Set Python and Java environment variables (symlink handles multi-arch)
ENV PYTHON_HOME=/usr
ENV JAVA_HOME=/usr/lib/jvm/temurin-21
ENV PATH="${JAVA_HOME}/bin:${PYTHON_HOME}/bin:${PATH}"

# Install Kotlin compiler directly
ARG KOTLIN_VERSION=2.0.21
RUN curl -L -o /tmp/kotlin.zip "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip" \
    && unzip /tmp/kotlin.zip -d /opt \
    && rm /tmp/kotlin.zip \
    && ln -s /opt/kotlinc/bin/kotlin /usr/local/bin/kotlin \
    && ln -s /opt/kotlinc/bin/kotlinc /usr/local/bin/kotlinc \
    && chown -R node:node /opt/kotlinc

# Set Kotlin environment variables
ENV KOTLIN_HOME=/opt/kotlinc

# Install Rust toolchain as node user
USER node
ENV RUSTUP_HOME=/home/node/.rustup
ENV CARGO_HOME=/home/node/.cargo
ENV PATH="${CARGO_HOME}/bin:${KOTLIN_HOME}/bin:${PATH}"

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable \
    && . "${CARGO_HOME}/env" \
    && rustup component add rustfmt clippy \
    && rustup component remove rust-docs

# Switch back to root for remaining setup
USER root

# Configure git identity for automated commits (eve-worker skills install)
RUN git config --system user.email "eve-worker@eve-horizon.local" \
    && git config --system user.name "Eve Worker"

COPY docker/worker/entrypoint.sh /usr/local/bin/eve-worker-entrypoint
COPY docker/worker/eve-skills /usr/local/bin/eve-skills
COPY docker/worker/orphan-reaper.sh /usr/local/bin/orphan-reaper
RUN chmod +x /usr/local/bin/eve-worker-entrypoint /usr/local/bin/eve-skills /usr/local/bin/orphan-reaper
COPY --chown=node:node . .

# Link CLIs globally (built by pnpm in dev mode)
RUN ln -s /app/packages/cli/bin/eve.js /usr/local/bin/eve

WORKDIR /app
# Switch to non-root user
USER node
ENTRYPOINT ["/usr/bin/tini", "--", "eve-worker-entrypoint"]
CMD ["pnpm", "--filter", "@eve/worker", "start:dev"]

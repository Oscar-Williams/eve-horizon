# rust:slim-bookworm
FROM rust@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37 AS build
RUN rustup component add rustfmt clippy \
    && rustup component remove rust-docs 2>/dev/null || true \
    && mkdir -p /toolchain \
    && cp -a /usr/local/cargo /toolchain/cargo \
    && cp -a /usr/local/rustup /toolchain/rustup

# env.sh for runtime setup
RUN printf '#!/bin/sh\nexport RUSTUP_HOME=/opt/eve/toolchains/rust/rustup\nexport CARGO_HOME=/opt/eve/toolchains/rust/cargo\nexport PATH="${CARGO_HOME}/bin:${PATH}"\n' > /toolchain/env.sh

# busybox:stable
FROM busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
COPY --from=build /toolchain /toolchain

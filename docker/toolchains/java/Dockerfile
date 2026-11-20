# eclipse-temurin:21-jdk-jammy
FROM eclipse-temurin@sha256:a8b6e4da662e2ff710459e76be515a14746045c7a7493531d0901ca10a231501 AS build
RUN mkdir -p /toolchain && cp -a /opt/java/openjdk /toolchain/jdk

# env.sh for runtime setup
RUN printf '#!/bin/sh\nexport JAVA_HOME=/opt/eve/toolchains/java/jdk\nexport PATH="${JAVA_HOME}/bin:${PATH}"\n' > /toolchain/env.sh

# busybox:stable
FROM busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
COPY --from=build /toolchain /toolchain
